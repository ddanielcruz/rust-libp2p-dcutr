use clap::Parser;
use futures::{
    executor::{block_on, ThreadPool}, FutureExt, StreamExt
};
use libp2p::{
    core::transport::{
        OrTransport, 
        upgrade
    }, 
    dns::DnsConfig,
    dcutr, identify, identity, noise, relay, tcp, ping, yamux,
    PeerId, 
    Transport, 
    swarm::{ NetworkBehaviour, SwarmBuilder, SwarmEvent },
    multiaddr::{ Multiaddr, Protocol }
};
use log::info;
use std::{ error::Error, net::Ipv4Addr, str::FromStr };

#[derive(Debug, Parser)]
#[clap(name = "libp2p DCUtR client")]
struct Opts {
    #[clap(long)]
    mode: Mode,

    #[clap(long)]
    secret_key_seed: u8,

    #[clap(long)]
    relay_address: Multiaddr,

    #[clap(long)]
    remote_peer_id: Option<PeerId>
}

#[derive(Clone, Debug, PartialEq, Parser)]
enum Mode {
    Dial,
    Listen
}

impl FromStr for Mode {
    type Err = String;
    fn from_str(mode: &str) -> Result<Self, Self::Err> {
        match mode {
            "dial" => Ok(Mode::Dial),
            "listen" => Ok(Mode::Listen),
            _ => Err("Expect either 'dial' or 'listen'.".to_string()),
        }
    }
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "Event", event_process = false)]
struct Behaviour {
    relay_client: relay::client::Behaviour,
    ping: ping::Behaviour,
    identify: identify::Behaviour,
    dcutr: dcutr::Behaviour
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum Event {
    Ping(ping::Event),
    Identify(identify::Event),
    Relay(relay::client::Event),
    DCUtR(dcutr::Event)
}

impl From<ping::Event> for Event {
    fn from(e: ping::Event) -> Self {
        Event::Ping(e)
    }
}

impl From<identify::Event> for Event {
    fn from(e: identify::Event) -> Self {
        Event::Identify(e)
    }
}

impl From<relay::client::Event> for Event {
    fn from(e: relay::client::Event) -> Self {
        Event::Relay(e)
    }
}

impl From<dcutr::Event> for Event {
    fn from(e: dcutr::Event) -> Self {
        Event::DCUtR(e)
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // Initialize the logger from the RUST_LOG environment variable
    env_logger::init();

    // Parse the command line arguments using clap crate
    let opts = Opts::parse();

    // Generate peer ID from the secret key seed
    let local_key = generate_ed25519(opts.secret_key_seed);
    let local_peer_id = PeerId::from(local_key.public());
    info!("Local peer ID: {local_peer_id:?}");

    // Create a new relay transport and client for the local peer
    let (relay_transport, client) = relay::client::new(local_peer_id);
    
    // Create a new TCP transport and DNS resolver if relay transport fails
    let transport = OrTransport::new(
        relay_transport,
        block_on(DnsConfig::system(tcp::async_io::Transport::new(
            tcp::Config::default().port_reuse(true)
        )))
        .unwrap()
    )
    .upgrade(upgrade::Version::V1)
    .authenticate(
        noise::NoiseAuthenticated::xx(&local_key)
        .expect("Signing libp2p-noise static DH keypair failed."),
    )
    .multiplex(yamux::YamuxConfig::default())
    .boxed();

    // Create a new behaviour for the local peer
    let behaviour = Behaviour {
        relay_client: client,
        ping: ping::Behaviour::new(ping::Config::new()),
        identify: identify::Behaviour::new(identify::Config::new(
            "/identify/1.0.0".to_string(),
            local_key.public())
        ),
        dcutr: dcutr::Behaviour::new(local_peer_id)
    };

    // Create a new swarm for the local peer
    let mut swarm = match ThreadPool::new() {
        Ok(tp) => SwarmBuilder::with_executor(transport, behaviour, local_peer_id, tp),
        Err(_) => SwarmBuilder::without_executor(transport, behaviour, local_peer_id)
    }
    .build();

    swarm.listen_on(
        Multiaddr::empty()
            .with("0.0.0.0".parse::<Ipv4Addr>().unwrap().into())
            .with(Protocol::Tcp(0)),
    )
    .unwrap();

    // Wait to listen on all interfaces
    block_on(async {
        let mut delay = futures_timer::Delay::new(std::time::Duration::from_secs(1)).fuse();
        loop {
            futures::select! {
                event = swarm.next() => {
                    match event.unwrap() {
                        SwarmEvent::NewListenAddr { address, .. } => {
                            info!("Listening on {address:?}");
                        }
                        event => panic!("{event:?}")
                    }
                }
                _ = delay => {
                    // Likely listening on all interfaces now, thus continuing by breaking the loop
                    break;
                }
            }
        }
    });

    // Connect to the relay server. Not for the reservation or relayed connection, but to (a) learn
    // our local public address and (b) enable a freshly started relay to learn its public address.
    swarm.dial(opts.relay_address.clone()).unwrap();
    block_on(async {
        let mut learned_observed_addr = false;
        let mut told_relay_observed_addr = false;

        loop {
            match swarm.next().await.unwrap() {
                SwarmEvent::NewListenAddr { .. } => {}
                SwarmEvent::Dialing { .. } => {}
                SwarmEvent::ConnectionEstablished { .. } => {}
                SwarmEvent::Behaviour(Event::Ping(_)) => {}
                SwarmEvent::Behaviour(Event::Identify(identify::Event::Sent { .. })) => {
                    info!("Told relay its public address.");
                    told_relay_observed_addr = true;
                }
                SwarmEvent::Behaviour(Event::Identify(identify::Event::Received {
                    info: identify::Info { observed_addr, .. },
                    ..
                })) => {
                    info!("Relay told us our public address: {:?}", observed_addr);
                    learned_observed_addr = true;
                }
                event => panic!("{event:?}"),
            }

            if learned_observed_addr && told_relay_observed_addr {
                break;
            }
        }
    });

    match opts.mode {
        Mode::Dial => {
            swarm
                .dial(
                    opts.relay_address
                        .with(Protocol::P2pCircuit)
                        .with(Protocol::P2p(opts.remote_peer_id.unwrap().into())),
                )
                .unwrap();
        }
        Mode::Listen => {
            swarm
                .listen_on(opts.relay_address.with(Protocol::P2pCircuit))
                .unwrap();
        }
    }

    block_on(async {
        loop {
            match swarm.next().await.unwrap() {
                SwarmEvent::NewListenAddr { address, .. } => {
                    info!("Listening on {:?}", address);
                }
                SwarmEvent::Behaviour(Event::Relay(
                    relay::client::Event::ReservationReqAccepted { .. },
                )) => {
                    assert!(opts.mode == Mode::Listen);
                    info!("Relay accepted our reservation request.");
                }
                SwarmEvent::Behaviour(Event::Relay(event)) => {
                    info!("RELAY: {:?}", event)
                }
                SwarmEvent::Behaviour(Event::DCUtR(event)) => {
                    info!("DCUtR: {:?}", event)
                }
                SwarmEvent::Behaviour(Event::Identify(event)) => {
                    info!("Identify: {:?}", event)
                }
                SwarmEvent::Behaviour(Event::Ping(_)) => {}
                SwarmEvent::ConnectionEstablished {
                    peer_id, endpoint, ..
                } => {
                    info!("Established connection to {:?} via {:?}", peer_id, endpoint);
                }
                SwarmEvent::OutgoingConnectionError { peer_id, error } => {
                    info!("Outgoing connection error to {:?}: {:?}", peer_id, error);
                }
                _ => {}
            }
        }
    })
}

fn generate_ed25519(secret_key_seed: u8) -> identity::Keypair {
    let mut bytes = [0u8; 32];
    bytes[0] = secret_key_seed;
    
    identity::Keypair::ed25519_from_bytes(bytes).expect("Invalid secret key seed length")
}
