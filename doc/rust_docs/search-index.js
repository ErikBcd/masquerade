var searchIndex = new Map(JSON.parse('[\
["connect_ip_client",{"t":"HH","n":["main","read_config"],"q":[[0,"connect_ip_client"],[2,"core::error"],[3,"alloc::boxed"],[4,"core::result"],[5,"masquerade_proxy::connect_ip::client"],[6,"masquerade_proxy::common"]],"i":[0,0],"f":"{{}{{h{b{f{d}}}}}}{{}{{h{jl}}}}","D":"`","p":[[1,"unit"],[10,"Error",2],[5,"Box",3],[6,"Result",4],[5,"ClientConfig",5],[6,"ConfigError",6]],"r":[],"b":[],"c":"OjAAAAAAAAA=","e":"OjAAAAEAAAAAAAIAEAAAAAAAAQACAA=="}],\
["masquerade_proxy",{"t":"CCCGPGPPPPSSSSSPPFPNNNNNNOHHHONNNNNNNHHHHNNNHHHHONNNNNNNNNNHHOOOOOCCCSSFPFFPFPSFGGFPPPPGSKPSFFPPPONNNNONNNNNNNNNNNNNNNNNNNNNNOONNNNNNONNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNMOONNNNNNNNNNNOOOOOOOOOOOONNNNNHOOONNNNNONNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNFFFGFFPPOOONNNNNNNNNNNNONNNNOONNNOOOOOONNNNNNNNNHNHOOONNNNNNHHHOOOOOOHNNOHOOOOONNNNNNNNNNNNNNNNNNNNNOFFGFSSFPPNNNNNNNNNNHHHNNNNNNNNHNNNNNNNNNNNNNNNNHHHHHHNNNNNOOOHHHNNNNNNNNNNNNNNNNNNNNNNNHFGFIFIPPFFSPFFSFFIHOHONNNNNNNNNNNNNNNNNNNNNOOOHNNNNNNOOOHOHOONNHOOOONNNNNONNNNNNNNNNHHHOOOOOONNNNNNNNNNONOOOOOOOOHOOONONOHOOOOOONNNNNNNNNNNNNNNNNNNNNNNNNHNNNNNNNNNN","n":["common","connect_ip","server","ConfigError","ConfigFileError","Content","Data","Datagram","Finished","Headers","MAX_DATAGRAM_SIZE","MAX_INT_LEN_1","MAX_INT_LEN_2","MAX_INT_LEN_4","MAX_VAR_INT","MissingArgument","Request","ToSend","WrongArgument","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","content","decode_var_int","decode_var_int_get_length","encode_var_int","finished","fmt","fmt","fmt","fmt","from","from","from","get_next_ipv4","hdrs_to_strings","hex_dump","interrupted","into","into","into","make_qlog_writer","mint_token","send_h3_dgram","split_ip_prefix","stream_id","to_string","try_from","try_from","try_from","try_into","try_into","try_into","type_id","type_id","type_id","validate_token","would_block","data","headers","headers","payload","stream_id_sender","capsules","client","util","ADDRESS_ASSIGN_ID","ADDRESS_REQUEST_ID","AddressAssign","AddressAssign","AddressRange","AddressRequest","AddressRequest","AssignedAddress","BufferTooShort","CLIENT_HELLO_ID","Capsule","CapsuleParseError","CapsuleType","ClientHello","ClientHello","InvalidCapsuleType","InvalidIPVersion","InvalidLength","IpLength","MAX_CLIENT_HELLO_ID_LEN","OctetsExt","Other","ROUTE_ADVERTISEMENT_ID","RequestedAddress","RouteAdvertisement","RouteAdvertisement","V4","V6","addr_ranges","as_address_assign","as_address_request","as_client_hello","as_route_advertisement","assigned_address","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","capsule_id","capsule_type","create_new","create_new","create_new","create_sendable","create_sendable","create_sendable","end_ip","eq","eq","eq","eq","eq","eq","eq","eq","eq","eq","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","from","from","from","from","from","from","from","from","from","from","from","get_u128","id","id_length","into","into","into","into","into","into","into","into","into","into","into","ip_address","ip_address","ip_prefix_len","ip_prefix_len","ip_proto","ip_version","ip_version","ip_version","length","length","length","length","new","new","new","new","new","read_ip","request_id","request_id","requested","serialize","serialize","serialize","serialize","serialize","start_ip","to_string","to_string","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","ClientConfig","ConnectIPClient","ConnectIpInfo","Direction","IpMessage","QuicStream","ToClient","ToServer","ack_delay_exponent","allowed_ips","assigned_ip","borrow","borrow","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","client_name","clone","clone","clone_into","clone_into","congestion_algorithm","create_qlog_file","create_quic_conn","create_tun","deserialize","dir","disable_active_migration","discover_pmtu","enable_hystart","flow_id","flow_id","fmt","fmt","fmt","from","from","from","from","from","from","generate_cid_and_reset_token","get_udp","handle_ip_connect_stream","interface_address","interface_gateway","interface_name","into","into","into","into","into","into","ip_dispatcher_t","ip_handler_t","ip_receiver_t","max_ack_delay","max_idle_timeout","max_pacing_rate","message","mtu","qlog_file_path","quic_conn_handler","run","serialize","server_address","set_client_ip_and_route","static_address","stream_id","stream_id","stream_sender","thread_channel_max","to_owned","to_owned","to_string","try_from","try_from","try_from","try_from","try_from","try_from","try_into","try_into","try_into","try_into","try_into","try_into","type_id","type_id","type_id","type_id","type_id","type_id","use_static_address","HandleIPError","IPError","Ipv4CheckError","QUICStreamError","TCP_ID","UDP_ID","UdpBindError","WrongChecksumError","WrongSizeError","borrow","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","calculate_tcp_udp_checksum","check_ipv4_packet","checksum_add","clone","clone","clone","clone","clone_into","clone_into","clone_into","clone_into","encapsulate_ipv4","eq","eq","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","fmt","from","from","from","from","from","get_ip_header_length","get_ip_version","get_ipv4_hdr_checksum","get_ipv4_pkt_dest","get_ipv4_pkt_source","get_ipv4_ttl","into","into","into","into","into","message","message","message","recalculate_checksum","set_ipv4_pkt_destination","set_ipv4_pkt_source","to_owned","to_owned","to_owned","to_owned","to_string","to_string","to_string","to_string","try_from","try_from","try_from","try_from","try_from","try_into","try_into","try_into","try_into","try_into","type_id","type_id","type_id","type_id","type_id","update_ipv4_checksum","Client","ClientError","ClientHandler","ClientMap","ConnectIpClient","ConnectIpClientList","HandshakeFail","HttpFail","IpConnectSession","IpRegisterRequest","MAX_CHANNEL_MESSAGES","Other","QuicReceived","RunBeforeBindError","STANDARD_NETMASK","Server","ServerConfig","StaticClientMap","_path_to_socketaddr","ack_delay_exponent","add_static_client_config","assigned_addr","bind","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","callback","client_config_path","client_ip","client_register_handler","clone","clone","clone","clone_into","clone_into","clone_into","congestion_algorithm","conn","connect_ip_clients","connect_ip_handler","connect_ip_session","create_http3_conn","create_qlog_file","data","default","deserialize","destroy_tun_interface","disable_active_migration","discover_pmtu","enable_hystart","flow_id","fmt","fmt","fmt","fmt","fmt","former_ip","from","from","from","from","from","from","from","from","from","from","get_next_free_ip","handle_client","handle_http3_event","handler_thread","http3_sender","id","id","interface_address","interface_name","into","into","into","into","into","into","into","into","into","into","ip_h3_sender","listen_addr","local_uplink_device_ip","local_uplink_device_name","max_ack_delay","max_idle_timeout","max_pacing_rate","mtu","qlog_file_path","quic_receiver","read_known_clients","recv_info","register_handler","requested_address","run","sender","serialize","server_address","set_ip_settings","socket","socket","static_addr","static_addr","static_clients","stream_id","to_owned","to_owned","to_owned","to_string","to_string","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_from","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","try_into","tun_socket_handler","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id","type_id"],"q":[[0,"masquerade_proxy"],[3,"masquerade_proxy::common"],[61,"masquerade_proxy::common::Content"],[66,"masquerade_proxy::connect_ip"],[69,"masquerade_proxy::connect_ip::capsules"],[244,"masquerade_proxy::connect_ip::client"],[345,"masquerade_proxy::connect_ip::util"],[433,"masquerade_proxy::server"],[597,"alloc::vec"],[598,"core::fmt"],[599,"core::net::ip_addr"],[600,"core::result"],[601,"quiche::h3"],[602,"alloc::string"],[603,"std::io::error"],[604,"std::fs"],[605,"std::io::buffered::bufwriter"],[606,"quiche::packet"],[607,"core::net::socket_addr"],[608,"quiche"],[609,"core::option"],[610,"core::any"],[611,"octets"],[612,"tokio::net::udp"],[613,"tun2::async::unix_device"],[614,"tun2::error"],[615,"serde::de"],[616,"ring::rand"],[617,"tokio::sync::mpsc::bounded"],[618,"tokio::io::split"],[619,"serde::ser"],[620,"core::error"],[621,"alloc::boxed"],[622,"tokio::net::addr"],[623,"std::collections::hash::map"],[624,"tokio::sync::mutex"],[625,"alloc::sync"],[626,"tokio::sync::mpsc::unbounded"]],"i":[0,0,0,0,9,0,12,12,12,12,0,0,0,0,0,9,12,0,9,9,12,13,9,12,13,13,0,0,0,13,9,9,12,13,9,12,13,0,0,0,0,9,12,13,0,0,0,0,13,9,9,12,13,9,12,13,9,12,13,0,0,87,88,89,90,88,0,0,0,0,0,0,39,0,0,39,0,38,0,0,0,0,0,39,38,38,38,0,0,0,38,0,0,0,39,40,40,37,33,33,33,33,34,38,39,40,33,36,34,41,35,42,37,43,38,39,40,33,36,34,41,35,42,37,43,33,33,36,34,35,36,34,35,43,39,40,33,36,34,41,35,42,37,43,38,38,39,40,40,33,36,34,41,35,42,37,43,38,39,40,33,36,34,41,35,42,37,43,44,36,36,38,39,40,33,36,34,41,35,42,37,43,41,42,41,42,43,41,42,43,36,34,35,37,33,36,34,35,37,0,41,42,35,33,36,34,35,37,43,38,40,38,39,40,33,36,34,41,35,42,37,43,38,39,40,33,36,34,41,35,42,37,43,38,39,40,33,36,34,41,35,42,37,43,0,0,0,0,0,0,56,56,48,48,49,91,62,50,48,56,49,91,62,50,48,56,49,48,48,49,48,49,48,48,50,50,48,62,48,48,48,91,49,48,48,56,91,62,50,48,56,49,0,50,0,48,48,48,91,62,50,48,56,49,0,0,0,48,48,48,62,48,48,0,50,48,48,0,48,91,49,91,48,48,49,48,91,62,50,48,56,49,91,62,50,48,56,49,91,62,50,48,56,49,48,0,0,0,0,0,0,0,66,66,58,67,16,68,66,58,67,16,68,66,0,0,0,58,67,16,68,58,67,16,68,0,16,66,58,58,67,67,16,16,68,68,66,58,67,16,68,66,0,0,0,0,0,0,58,67,16,68,66,67,16,68,0,0,0,58,67,16,68,58,67,16,68,58,67,16,68,66,58,67,16,68,66,58,67,16,68,66,0,0,0,0,0,0,0,84,84,0,0,0,84,0,0,0,0,0,0,0,79,0,75,70,74,92,93,82,86,75,79,84,80,70,74,92,93,82,86,75,79,84,80,70,74,79,86,0,75,79,80,75,79,80,79,82,86,0,86,0,79,92,70,79,0,79,79,79,93,79,79,84,80,80,74,74,92,93,82,86,75,79,84,80,70,0,0,0,93,86,74,75,79,79,74,92,93,82,86,75,79,84,80,70,93,70,79,79,79,79,79,79,79,82,0,92,86,74,70,75,79,79,0,82,70,74,75,86,93,75,79,80,79,80,74,92,93,82,86,75,79,84,80,70,74,92,93,82,86,75,79,84,80,70,0,74,92,93,82,86,75,79,84,80,70],"f":"```````````````````{{{b{c}}}{{b{e}}}{}{}}00{{{b{dc}}}{{b{de}}}{}{}}00`{{{b{{h{f}}}}}{{l{j{b{{h{f}}}}}}}}{{{b{{h{f}}}}}{{l{jn}}}}{j{{A`{f}}}}`{{{b{Ab}}{b{dAd}}}Af}0{{{b{Ah}}{b{dAd}}}Af}{{{b{Aj}}{b{dAd}}}Af}{cc{}}00{{AlAn}{{Bb{AlB`}}}}{{{b{{h{Bd}}}}}{{A`{{l{BfBf}}}}}}{{{b{{h{f}}}}}Bf}{{{b{Bh}}}Bj}{ce{}{}}00{{{b{Bl}}{b{Bl}}{b{Bl}}}{{C`{Bn}}}}{{{b{Cb}}{b{Cd}}}{{A`{f}}}}{{{b{dCf}}j{b{{h{f}}}}}{{Cj{Ch}}}}{Bf{{l{Bf{Cl{f}}}}}}`{{{b{c}}}Bf{}}{c{{Bb{e}}}{}{}}00000{{{b{c}}}Cn{}}00{{{b{Cd}}{b{{h{f}}}}}{{Cl{D`}}}}9`````````````````````````````````````{{{b{Db}}}{{Cl{{b{Dd}}}}}}{{{b{Db}}}{{Cl{{b{Df}}}}}}{{{b{Db}}}{{Cl{{b{Dh}}}}}}{{{b{Db}}}{{Cl{{b{Dj}}}}}}`{{{b{c}}}{{b{e}}}{}{}}0000000000{{{b{dc}}}{{b{de}}}{}{}}0000000000``{Bf{{Bb{DbDl}}}}{{Al{Cl{f}}{Cl{j}}}Db}0{Bf{{Bb{{A`{f}}Dl}}}}{{Al{Cl{f}}{Cl{j}}}{{A`{f}}}}0`{{{b{Dn}}{b{Dn}}}Bj}{{{b{E`}}{b{E`}}}Bj}{{{b{Db}}{b{Db}}}Bj}{{{b{Dh}}{b{Dh}}}Bj}{{{b{Dd}}{b{Dd}}}Bj}{{{b{Eb}}{b{Eb}}}Bj}{{{b{Df}}{b{Df}}}Bj}{{{b{Ed}}{b{Ed}}}Bj}{{{b{Dj}}{b{Dj}}}Bj}{{{b{Ef}}{b{Ef}}}Bj}{{{b{Dl}}{b{dAd}}}Af}0{{{b{Dn}}{b{dAd}}}Af}{{{b{E`}}{b{dAd}}}Af}0{{{b{Db}}{b{dAd}}}Af}{{{b{Dh}}{b{dAd}}}Af}{{{b{Dd}}{b{dAd}}}Af}{{{b{Eb}}{b{dAd}}}Af}{{{b{Df}}{b{dAd}}}Af}{{{b{Ed}}{b{dAd}}}Af}{{{b{Dj}}{b{dAd}}}Af}{{{b{Ef}}{b{dAd}}}Af}{cc{}}0000000000{{{b{dEh}}}{{Bb{EjDl}}}}``{ce{}{}}0000000000````````````{{{b{{h{f}}}}}{{Bb{DbDl}}}}{{{b{dEl}}}{{Bb{DhDl}}}}{{{b{dEl}}}{{Bb{DdDl}}}}{{{b{dEl}}}{{Bb{DfDl}}}}{{{b{dEl}}}{{Bb{DjDl}}}}{{{b{dEl}}{b{f}}}{{Bb{E`Dl}}}}```{{{b{Db}}{b{d{h{f}}}}}{{A`{f}}}}{{{b{Dh}}{b{dEn}}}Ch}{{{b{Dd}}{b{dEn}}}Ch}{{{b{Df}}{b{dEn}}}Ch}{{{b{Dj}}{b{dEn}}}Ch}`{{{b{c}}}Bf{}}0{c{{Bb{e}}}{}{}}000000000000000000000{{{b{c}}}Cn{}}0000000000```````````{{{b{c}}}{{b{e}}}{}{}}00000{{{b{dc}}}{{b{de}}}{}{}}00000`{{{b{F`}}}F`}{{{b{Fb}}}Fb}{{{b{c}}{b{de}}}Ch{}{}}0``{{{b{Fd}}{b{dFf}}{b{F`}}}{{Bb{CfFh}}}}{{{b{Fd}}{b{Bf}}{b{Bf}}{b{Bf}}{b{Bf}}{b{Bf}}}{{Bb{FjFl}}}}{c{{Bb{F`}}}Fn}``````{{{b{F`}}{b{dAd}}}Af}0{{{b{G`}}{b{dAd}}}Af}{cc{}}00000{{{b{c}}}{{l{D`Ej}}}Gb}{{{b{Fd}}{b{Bf}}}{{Bb{FfGd}}}}{{{Gf{Aj}}{Gh{Ah}}F`}Ch}```{ce{}{}}00000{{{Gh{{A`{f}}}}{Gj{Fj}}}Ch}{{{Gh{Gl}}{Gh{Fb}}{Gf{Aj}}{Gf{{A`{f}}}}Al}Ch}{{{Gf{Gl}}{Gn{Fj}}}Ch}``````{{{Gf{Gl}}{Gf{Fb}}{Gf{Aj}}{Gh{Aj}}CfFfF`}Ch}{{{b{Fd}}F`}Ch}{{{b{F`}}c}BbH`}`{{{b{Bf}}{b{Bf}}{b{Bf}}{b{Bf}}{b{Bf}}}Ch}`````{{{b{c}}}e{}{}}0{{{b{c}}}Bf{}}{c{{Bb{e}}}{}{}}00000000000{{{b{c}}}Cn{}}00000``````````{{{b{c}}}{{b{e}}}{}{}}0000{{{b{dc}}}{{b{de}}}{}{}}0000{{{b{{h{f}}}}{b{{h{f}}}}f{b{d{h{f}}}}n}Ch}{{{b{{h{f}}}}Hb}{{Bb{ChHd}}}}{{n{b{{h{f}}}}}An}{{{b{Gd}}}Gd}{{{b{Hf}}}Hf}{{{b{B`}}}B`}{{{b{Hh}}}Hh}{{{b{c}}{b{de}}}Ch{}{}}000{{{A`{f}}{b{j}}{b{j}}}Aj}{{{b{B`}}{b{B`}}}Bj}{{{b{Hd}}{b{Hd}}}Bj}{{{b{Gd}}{b{dAd}}}Af}0{{{b{Hf}}{b{dAd}}}Af}0{{{b{B`}}{b{dAd}}}Af}0{{{b{Hh}}{b{dAd}}}Af}0{{{b{Hd}}{b{dAd}}}Af}{cc{}}0000{{{b{{h{f}}}}}f}0{{{b{{h{f}}}}}Hb}{{{b{{h{f}}}}}Al}02{ce{}{}}0000```{{{b{d{h{f}}}}}Ch}{{{b{d{h{f}}}}{b{Al}}}Ch}0{{{b{c}}}e{}{}}000{{{b{c}}}Bf{}}000{c{{Bb{e}}}{}{}}000000000{{{b{c}}}Cn{}}0000{{{b{d{h{f}}}}f}Ch}``````````````````{{{b{{h{f}}}}}{{Cl{Cd}}}}`{{AlBf{b{Bl}}{b{Hj}}}Ch}`{{{b{dHl}}c}{{Bb{Ch{I`{Hn}}}}}Ib}{{{b{c}}}{{b{e}}}{}{}}000000000{{{b{dc}}}{{b{de}}}{}{}}000000000```{{{Gh{Id}}{Il{{Ij{{Ih{AlIf}}}}}}HjBf}Ch}{{{b{If}}}If}{{{b{In}}}In}{{{b{J`}}}J`}{{{b{c}}{b{de}}}Ch{}{}}00```{{jj{Jb{Aj}}{Gh{{A`{f}}}}{Gf{{A`{f}}}}{Gh{Ah}}AlHj{Gf{Id}}}Ch}`{{{b{dJd}}}{{Cl{Jf}}}}``{{}Hl}{c{{Bb{In}}}Fn}{{}Ch}````{{{b{In}}{b{dAd}}}Af}0{{{b{Jh}}{b{dAd}}}Af}{{{b{J`}}{b{dAd}}}Af}0`{cc{}}000000000{{Al{b{{Jj{{Ih{AlIf}}}}}}}{{Cl{Al}}}}{{JdAl{b{{Gf{{A`{f}}}}}}{Il{{Ij{{Ih{AlIf}}}}}}Hj{Gf{Id}}}Ch}{{{b{dJf}}{b{dJd}}{b{dJl}}{b{{Gf{{A`{f}}}}}}}{{Bb{ChJh}}}}``````{ce{}{}}000000000`{{{b{Hl}}}{{Cl{Cd}}}}````````{{{b{Bf}}}{{Bb{HjAb}}}}```{{{b{Hl}}In}{{Bb{Ch{I`{Hn}}}}}}`{{{b{In}}c}BbH`}`{In{{Bb{Ch{I`{Hn}}}}}}``````{{{b{c}}}e{}{}}00{{{b{c}}}Bf{}}0{c{{Bb{e}}}{}{}}0000000000000000000{{{Il{{Ij{{Ih{AlIf}}}}}}{Gh{{A`{f}}}}In}Ch}{{{b{c}}}Cn{}}000000000","D":"AAb","p":[[1,"reference"],[0,"mut"],[1,"u8"],[1,"slice"],[1,"u64"],[1,"tuple"],[1,"usize"],[5,"Vec",597],[6,"ConfigError",3],[5,"Formatter",598],[8,"Result",598],[6,"Content",3],[5,"ToSend",3],[5,"Ipv4Addr",599],[1,"u32"],[5,"IPError",345],[6,"Result",600],[5,"Header",601],[5,"String",602],[5,"Error",603],[1,"bool"],[1,"str"],[5,"File",604],[5,"BufWriter",605],[5,"Header",606],[6,"SocketAddr",607],[5,"Connection",608],[1,"unit"],[8,"Result",608],[6,"Option",609],[5,"TypeId",610],[5,"ConnectionId",606],[5,"Capsule",69],[5,"AddressAssign",69],[5,"AddressRequest",69],[5,"ClientHello",69],[5,"RouteAdvertisement",69],[6,"CapsuleParseError",69],[6,"CapsuleType",69],[6,"IpLength",69],[5,"AssignedAddress",69],[5,"RequestedAddress",69],[5,"AddressRange",69],[10,"OctetsExt",69],[1,"u128"],[5,"Octets",611],[5,"OctetsMut",611],[5,"ClientConfig",244],[5,"ConnectIpInfo",244],[5,"ConnectIPClient",244],[5,"UdpSocket",612],[6,"Error",608],[5,"AsyncDevice",613],[6,"Error",614],[10,"Deserializer",615],[6,"Direction",244],[10,"SecureRandom",616],[5,"UdpBindError",345],[5,"Sender",617],[5,"Receiver",617],[5,"WriteHalf",618],[5,"IpMessage",244],[5,"ReadHalf",618],[10,"Serializer",619],[1,"u16"],[6,"Ipv4CheckError",345],[5,"HandleIPError",345],[5,"QUICStreamError",345],[8,"StaticClientMap",433],[5,"Server",433],[10,"Error",620],[5,"Box",621],[10,"ToSocketAddrs",622],[5,"IpRegisterRequest",433],[5,"ConnectIpClient",433],[5,"HashMap",623],[5,"Mutex",624],[5,"Arc",625],[5,"ServerConfig",433],[5,"RunBeforeBindError",433],[5,"UnboundedSender",626],[5,"Client",433],[5,"Connection",601],[6,"ClientError",433],[5,"MutexGuard",624],[5,"ClientHandler",433],[15,"Data",61],[15,"Request",61],[15,"Headers",61],[15,"Datagram",61],[5,"QuicStream",244],[5,"QuicReceived",433],[5,"IpConnectSession",433]],"r":[],"b":[[30,"impl-Debug-for-ConfigError"],[31,"impl-Display-for-ConfigError"],[144,"impl-Debug-for-CapsuleParseError"],[145,"impl-Display-for-CapsuleParseError"],[147,"impl-Debug-for-IpLength"],[148,"impl-Display-for-IpLength"],[283,"impl-Display-for-ClientConfig"],[284,"impl-Debug-for-ClientConfig"],[378,"impl-Display-for-UdpBindError"],[379,"impl-Debug-for-UdpBindError"],[380,"impl-Debug-for-HandleIPError"],[381,"impl-Display-for-HandleIPError"],[382,"impl-Display-for-IPError"],[383,"impl-Debug-for-IPError"],[384,"impl-Debug-for-QUICStreamError"],[385,"impl-Display-for-QUICStreamError"],[501,"impl-Display-for-ServerConfig"],[502,"impl-Debug-for-ServerConfig"],[504,"impl-Debug-for-RunBeforeBindError"],[505,"impl-Display-for-RunBeforeBindError"]],"c":"OjAAAAAAAAA=","e":"OzAAAAEAAMwBJAAAAAUABwAKABMADwAnAAIALwAAADEACgA9ACUAZwAYAIYAFwCpAAIAtwALAMkAAgDRACMA9gAAAPsAFwAVAQkAKAECADQBBQA7AQIAPwEtAG4BCQB5AQoAlAECAJoBFgCzAQMAuAEKAMUBAgDJARYA4QEKAO0BDgAGAgAACQIFABkCAAAbAgcAJAImAEwCCQA="}],\
["server",{"t":"HH","n":["main","read_config"],"q":[[0,"server"],[2,"core::error"],[3,"alloc::boxed"],[4,"core::result"],[5,"masquerade_proxy::server"],[6,"masquerade_proxy::common"]],"i":[0,0],"f":"{{}{{h{b{f{d}}}}}}{{}{{h{jl}}}}","D":"`","p":[[1,"unit"],[10,"Error",2],[5,"Box",3],[6,"Result",4],[5,"ServerConfig",5],[6,"ConfigError",6]],"r":[],"b":[],"c":"OjAAAAAAAAA=","e":"OjAAAAEAAAAAAAIAEAAAAAAAAQACAA=="}]\
]'));
if (typeof exports !== 'undefined') exports.searchIndex = searchIndex;
else if (window.initSearch) window.initSearch(searchIndex);