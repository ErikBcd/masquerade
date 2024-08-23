use log::error;
use masquerade_proxy::ip_connect::{capsules::*, util::{check_ipv4_packet, recalculate_checksum, IPError}};
use octets::OctetsMut;
use tokio::time::timeout;
use std::{net::Ipv4Addr, time::Duration};

mod common;

use masquerade_proxy::common::get_next_ipv4;

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
async fn addr_assign_capsule_parsing_test() {
    // first create example capsule ADDRESS_ASSIGN
    let mut buffer = [0; 128];

    {
        let mut addr_assign = OctetsMut::with_slice(&mut buffer);

        assert!(addr_assign.put_varint(ADDRESS_ASSIGN_ID).is_ok()); // Type
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
        ip_address: IpLength::V4(Ipv4Addr::new(192, 168, 0, 45).into()),
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

    // Test serialization
    let mut testbuf = [0; 128];
    cap.unwrap().serialize(&mut testbuf);

    assert_eq!(testbuf, buffer, "Testing deserialization: Serialized={:?} | Original={:?}", testbuf, buffer);

    // TODO: Test for other capsule types and the serialization
}

/**
 * Simple test to check if capsule parsing and serialization for 
 * ADRESS_REQUEST works
 */
#[test_log::test(tokio::test)]
async fn addr_request_capsule_parsing_test() {
    // first create example capsule ADDRESS_ASSIGN
    let mut buffer = [0; 128];

    {
        let mut addr_request = OctetsMut::with_slice(&mut buffer);

        assert!(addr_request.put_varint(ADDRESS_REQUEST_ID).is_ok()); // Type
        assert!(addr_request.put_varint(9).is_ok()); // Length
        assert!(addr_request.put_varint(0).is_ok()); // Request ID
        assert!(addr_request.put_u8(4).is_ok()); // IP Version 4
        assert!(addr_request.put_u32(Ipv4Addr::new(192, 168, 0, 45).into()).is_ok()); // IP 192.168.0.45
        assert!(addr_request.put_u8(24).is_ok()); // ip prefix
    }
    println!("Raw Testdata: {:?}", buffer);

    let cap = Capsule::new(&buffer)
        .map_err(|e| error!("Could not parse capsule! {:?}", e));

    let ass_addr = RequestedAddress {
        request_id: 0,
        ip_version: 4,
        ip_address: IpLength::V4(Ipv4Addr::new(192, 168, 0, 45).into()),
        ip_prefix_len: 24
    };
    let addr_request_real = AddressRequest {
        length: 9,
        requested: vec![ass_addr]
    };
    
    // Ensure both are the same
    assert_eq!(
        &cap.as_ref().unwrap().as_address_request().unwrap().length, 
        &addr_request_real.length, 
        "Testing on length: {} | {}",
        &cap.as_ref().unwrap().as_address_request().unwrap().length, 
        &addr_request_real.length, 
    );

    assert_eq!(
        &cap.as_ref().unwrap().as_address_request().unwrap().requested[0].request_id, 
        &addr_request_real.requested[0].request_id, 
        "Testing for request ID: {} | {}",
        &cap.as_ref().unwrap().as_address_request().unwrap().requested[0].request_id, 
        &addr_request_real.requested[0].request_id, 
    );

    assert_eq!(
        &cap.as_ref().unwrap().as_address_request().unwrap().requested[0].ip_version, 
        &addr_request_real.requested[0].ip_version, 
        "Testing for ip_version: {} | {}",
        &cap.as_ref().unwrap().as_address_request().unwrap().requested[0].ip_version, 
        &addr_request_real.requested[0].ip_version, 
    );

    assert_eq!(
        &cap.as_ref().unwrap().as_address_request().unwrap().requested[0].ip_address, 
        &addr_request_real.requested[0].ip_address, 
        "Testing for IP: {} | {}",
        &cap.as_ref().unwrap().as_address_request().unwrap().requested[0].ip_address, 
        &addr_request_real.requested[0].ip_address, 
    );

    assert_eq!(
        &cap.as_ref().unwrap().as_address_request().unwrap().requested[0].ip_prefix_len, 
        &addr_request_real.requested[0].ip_prefix_len, 
        "Testing for ip_prefix: {} | {}",
        &cap.as_ref().unwrap().as_address_request().unwrap().requested[0].ip_prefix_len, 
        &addr_request_real.requested[0].ip_prefix_len, 
    );

    // Test serialization
    let mut testbuf = [0; 128];
    cap.unwrap().serialize(&mut testbuf);

    assert_eq!(testbuf, buffer, "Testing deserialization: Serialized={:?} | Original={:?}", testbuf, buffer);
}

/**
 * Simple test to check if capsule parsing and serialization for 
 * ADRESS_REQUEST works
 */
#[test_log::test(tokio::test)]
async fn route_advertisement_parsing_test() {
    // first create example capsule ADDRESS_ASSIGN
    let mut buffer = [0; 128];

    {
        let mut addr_request = OctetsMut::with_slice(&mut buffer);

        assert!(addr_request.put_varint(ROUTE_ADVERTISEMENT_ID).is_ok()); // Type
        assert!(addr_request.put_varint(12).is_ok()); // Length
        assert!(addr_request.put_u8(4).is_ok()); // IP Version 4
        assert!(addr_request.put_u32(Ipv4Addr::new(192, 168, 0, 45).into()).is_ok()); // IP 192.168.0.45
        assert!(addr_request.put_u32(Ipv4Addr::new(192, 168, 0, 54).into()).is_ok()); // IP 192.168.0.45
        assert!(addr_request.put_u8(0).is_ok()); // ip prefix
    }
    println!("Raw Testdata: {:?}", buffer);

    let cap = Capsule::new(&buffer)
        .map_err(|e| error!("Could not parse capsule! {:?}", e));

    let ass_addr = AddressRange {
        ip_version: 4,
        start_ip: IpLength::V4(Ipv4Addr::new(192, 168, 0, 45).into()),
        end_ip: IpLength::V4(Ipv4Addr::new(192, 168, 0, 54).into()),
        ip_proto: 0
    };
    let route_real = RouteAdvertisement {
        length: 12,
        addr_ranges: vec![ass_addr]
    };
    
    // Ensure both are the same
    assert_eq!(
        &cap.as_ref().unwrap().as_route_advertisement().unwrap().length, 
        &route_real.length, 
        "Testing on length: {} | {}",
        &cap.as_ref().unwrap().as_route_advertisement().unwrap().length, 
        &route_real.length, 
    );

    assert_eq!(
        &cap.as_ref().unwrap().as_route_advertisement().unwrap().addr_ranges[0].ip_version, 
        &route_real.addr_ranges[0].ip_version, 
        "Testing for ip_version: {} | {}",
        &cap.as_ref().unwrap().as_route_advertisement().unwrap().addr_ranges[0].ip_version, 
        &route_real.addr_ranges[0].ip_version, 
    );

    assert_eq!(
        &cap.as_ref().unwrap().as_route_advertisement().unwrap().addr_ranges[0].start_ip, 
        &route_real.addr_ranges[0].start_ip, 
        "Testing for start_ip: {} | {}",
        &cap.as_ref().unwrap().as_route_advertisement().unwrap().addr_ranges[0].start_ip, 
        &route_real.addr_ranges[0].start_ip, 
    );

    assert_eq!(
        &cap.as_ref().unwrap().as_route_advertisement().unwrap().addr_ranges[0].end_ip, 
        &route_real.addr_ranges[0].end_ip, 
        "Testing for end_ip: {} | {}",
        &cap.as_ref().unwrap().as_route_advertisement().unwrap().addr_ranges[0].end_ip, 
        &route_real.addr_ranges[0].end_ip, 
    );

    assert_eq!(
        &cap.as_ref().unwrap().as_route_advertisement().unwrap().addr_ranges[0].ip_proto, 
        &route_real.addr_ranges[0].ip_proto, 
        "Testing for ip_proto: {} | {}",
        &cap.as_ref().unwrap().as_route_advertisement().unwrap().addr_ranges[0].ip_proto, 
        &route_real.addr_ranges[0].ip_proto, 
    );

    // Test serialization
    let mut testbuf = [0; 128];
    cap.unwrap().serialize(&mut testbuf);

    assert_eq!(testbuf, buffer, "Testing deserialization: Serialized={:?} | Original={:?}", testbuf, buffer);
}

/// Simple test for the get_next_ipv4 function.
/// 
#[test_log::test(tokio::test)]
async fn next_ip_test() {
    assert_eq!(
        get_next_ipv4(Ipv4Addr::new(192, 168, 0, 1), 0xFFFFFF00), 
        Ok(Ipv4Addr::new(192, 168, 0, 2)));

    assert_eq!(
        get_next_ipv4(Ipv4Addr::new(192, 168, 0, 255), 0xFFFF0000), 
        Ok(Ipv4Addr::new(192, 168, 1, 0)));

    assert_eq!(
        get_next_ipv4(Ipv4Addr::new(192, 168, 0, 255), 0xFFFFFF00), 
        Err(IPError { message: "Next address out of range!".to_owned()}));
}

#[test_log::test(tokio::test)]
async fn recalculate_checksum_test() {
    let udp_payload = [
        0x45, // ip ver 4, header length 20bytes (5*4)
        0x00, 
        0x00, 0x1e, // total length (30)
        0x93, 0x1d, // Identification
        0x40, 0x00, // flags
        0x3f,       // TTL (63)
        0x11,       // Protocol UDP (17)
        0x94, 0x9e, // Header checksum (correct)
        0x0a, 0x08, 0x00, 0x03, // Source address 10.8.0.3
        0x0a, 0x08, 0x00, 0x01, // Dest address 10.8.0.1 | End of IP header
        0xb3, 0x3e,             // UDP source port 45886
        0x04, 0xd2,             // UDP dest port 1234
        0x00, 0x0a,             // Length (10)
        0xd2, 0xab,             // Checksum (correct)
        0x61, 0x0a];            // Data

    let mut udp_payload_wrong = vec![
        0x45, // ip ver 4, header length 20bytes (5*4)
        0x00, 
        0x00, 0x1e, // total length (30)
        0x93, 0x1d, // Identification
        0x40, 0x00, // flags
        0x3f,       // TTL (63)
        0x11,       // Protocol UDP (17)
        0x94, 0x9d, // Header checksum (wrong)
        0x0a, 0x08, 0x00, 0x03, // Source address 10.8.0.3
        0x0a, 0x08, 0x00, 0x01, // Dest address 10.8.0.1 | End of IP header
        0xb3, 0x3e,             // UDP source port 45886
        0x04, 0xd2,             // UDP dest port 1234
        0x00, 0x0a,             // Length (10)
        0xd2, 0xaa,             // Checksum (wrong)
        0x61, 0x0a];            // Data

    // Assert that packet is wrong
    assert_eq!(check_ipv4_packet(udp_payload_wrong.as_slice(), 30), Err(masquerade_proxy::ip_connect::util::Ipv4CheckError::WrongChecksumError));

    // Recalculate checksum of wrong packet
    recalculate_checksum(&mut udp_payload_wrong);
    println!("UDP | Correct packet: {:02x?}", udp_payload);
    println!("UDP | Recalc  packet: {:02x?}", udp_payload_wrong);
    assert_eq!(udp_payload_wrong.as_slice(), udp_payload);

    // Check the check_ipv4_packet function
    assert_eq!(check_ipv4_packet(udp_payload.as_slice(), 30), Ok(()));

    // TCP test
    let tcp_payload = vec![
        0x45, 0x00, 0x00, 0x3c, 0x31, 0x22, 0x40, 0x00, 0x3f, 0x06, 
        0xdd, 0x31, // ip checksum (correct)
        0x0a, 0x08, 0x00, 0x03,
        0x5f, 0xd8, 0xc3, 0x85, // end IP header
        0xd0, 0xd8, 0x00, 0x50, 0x34, 0x7c, 0xe1, 0xc3, 0x00, 0x00, 0x00, 0x00,
        0xa0, 0x02, 0xfa, 0xf0, 
        0x87, 0x1f, // TCP checksum (correct)
        0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
        0x5b, 0x78, 0x55, 0xa6, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
    ];

    let mut tcp_payload_wrong = vec![
        0x45, 0x00, 0x00, 0x3c, 0x31, 0x22, 0x40, 0x00, 0x3f, 0x06, 
        0xdd, 0x3e, // ip checksum (correct)
        0x0a, 0x08, 0x00, 0x03,
        0x5f, 0xd8, 0xc3, 0x85, // end IP header
        0xd0, 0xd8, 0x00, 0x50, 0x34, 0x7c, 0xe1, 0xc3, 0x00, 0x00, 0x00, 0x00,
        0xa0, 0x02, 0xfa, 0xf0, 
        0x87, 0x1e, // TCP checksum (correct)
        0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a,
        0x5b, 0x78, 0x55, 0xa6, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
    ];

    // Recalculate checksum of wrong packet
    recalculate_checksum(&mut tcp_payload_wrong);
    println!("TCP | Correct packet: {:?}", tcp_payload);
    println!("TCP | Recalc  packet: {:?}", tcp_payload_wrong);
    assert_eq!(tcp_payload_wrong.as_slice(), tcp_payload);

    

}