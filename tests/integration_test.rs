use log::error;
use masquerade_proxy::ip_connect::capsules::{AddressAssign, AssignedAddress, Capsule, IP_Length};
use octets::OctetsMut;
use tokio::time::timeout;
use std::{net::Ipv4Addr, str::FromStr, time::Duration};

mod common;

// TODO: gracefully exit the tests (implement Drop for server and clients)

/**
 * Simple test with single stream in a single QUIC connection. No multiplexing.
 */
#[test_log::test(tokio::test)]
async fn end_to_end_http1_tcp_test() {
    let timeout_duration = Duration::from_secs(5);    

    let (client_stream, server_stream) = timeout(timeout_duration, common::setup_http1_client()).await.unwrap().unwrap();
    
    let (client_stream, server_stream) =  common::assert_stream_connected(client_stream, server_stream, 74783).await;
    let (client_stream, server_stream) = common::assert_stream_connected(server_stream, client_stream, 84783).await;
    let (client_stream, server_stream) = common::assert_stream_connected(server_stream, client_stream, 84783).await;
    let (_, _) =  common::assert_stream_connected(client_stream, server_stream, 84783).await;
}

/**
 * Simple test with single stream in a single QUIC connection. No multiplexing.
 */
#[test_log::test(tokio::test)]
async fn end_to_end_socks5_tcp_test() {
    let timeout_duration = Duration::from_secs(5);    

    let (client_stream, server_stream) = timeout(timeout_duration, common::setup_socks5_tcp_client()).await.unwrap().unwrap();
    let (client_stream, server_stream) =  common::assert_stream_connected(client_stream, server_stream, 74783).await;
    let (client_stream, server_stream) = common::assert_stream_connected(server_stream, client_stream, 84783).await;
    let (client_stream, server_stream) = common::assert_stream_connected(server_stream, client_stream, 84783).await;
    let (_, _) =  common::assert_stream_connected(client_stream, server_stream, 84783).await;
}


/**
 * Simple test with single stream and single flow in a single QUIC connection. No multiplexing.
 */
#[test_log::test(tokio::test)]
async fn end_to_end_socks5_udp_test() {
    let timeout_duration = Duration::from_secs(5);    

    let (client_socket, _client_stream) = timeout(timeout_duration, common::setup_socks5_udp_client()).await.unwrap().unwrap();
    
    println!("socks5 udp client set up, testing now");
    common::assert_socks5_socket_connected(&client_socket, 1000).await;
}

/**
 * Simple test to check if capsule parsing and serialization works
 */
#[test_log::test(tokio::test)]
async fn capsule_parsing() {
    // first create example capsule ADDRESS_ASSIGN
    let mut buffer = [0; 128];

    {
        let mut addr_assign = OctetsMut::with_slice(&mut buffer);

        assert!(addr_assign.put_varint(1).is_ok()); // Type
        assert!(addr_assign.put_varint(9).is_ok());// Length
        assert!(addr_assign.put_varint(0).is_ok()); // Request ID
        assert!(addr_assign.put_u8(4).is_ok()); // IP Version 4
        assert!(addr_assign.put_u32(Ipv4Addr::new(192, 168, 0, 45).into()).is_ok()); // IP 192.168.0.45
        assert!(addr_assign.put_u8(24).is_ok()); // ip prefix
    }
    println!("Raw Testdata: {:?}", buffer);

    let cap = Capsule::new(&buffer)
        .map_err(|e| error!("Could not parse capsule! {:?}", e));

    let ass_addr = AssignedAddress {
        request_id: 0,
        ip_version: 4,
        ip_address: IP_Length::V4(Ipv4Addr::new(192, 168, 0, 45).into()),
        ip_prefix_len: 24
    };
    let addr_assign_real = AddressAssign {
        length: 9,
        assigned_address: vec![ass_addr]
    };
    
    // Ensure both are the same
    assert_eq!(
        &cap.as_ref().unwrap().as_address_assign().unwrap().length, 
        &addr_assign_real.length, 
        "Testing on length: {} | {}",
        &cap.as_ref().unwrap().as_address_assign().unwrap().length, 
        &addr_assign_real.length, 
    );

    assert_eq!(
        &cap.as_ref().unwrap().as_address_assign().unwrap().assigned_address[0].request_id, 
        &addr_assign_real.assigned_address[0].request_id, 
        "Testing for request ID: {} | {}",
        &cap.as_ref().unwrap().as_address_assign().unwrap().assigned_address[0].request_id, 
        &addr_assign_real.assigned_address[0].request_id, 
    );

    assert_eq!(
        &cap.as_ref().unwrap().as_address_assign().unwrap().assigned_address[0].ip_version, 
        &addr_assign_real.assigned_address[0].ip_version, 
        "Testing for ip_version: {} | {}",
        &cap.as_ref().unwrap().as_address_assign().unwrap().assigned_address[0].ip_version, 
        &addr_assign_real.assigned_address[0].ip_version, 
    );

    assert_eq!(
        &cap.as_ref().unwrap().as_address_assign().unwrap().assigned_address[0].ip_address, 
        &addr_assign_real.assigned_address[0].ip_address, 
        "Testing for IP: {} | {}",
        &cap.as_ref().unwrap().as_address_assign().unwrap().assigned_address[0].ip_address, 
        &addr_assign_real.assigned_address[0].ip_address, 
    );

    assert_eq!(
        &cap.as_ref().unwrap().as_address_assign().unwrap().assigned_address[0].ip_prefix_len, 
        &addr_assign_real.assigned_address[0].ip_prefix_len, 
        "Testing for ip_prefix: {} | {}",
        &cap.as_ref().unwrap().as_address_assign().unwrap().assigned_address[0].ip_prefix_len, 
        &addr_assign_real.assigned_address[0].ip_prefix_len, 
    );

    // TODO: Test for other capsule types and the serialization
}


