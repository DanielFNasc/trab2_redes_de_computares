// SPDX-FileCopyrightText: 2018 Nate Foster
// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */

#include <core.p4>
#include <v1model.p4>

/********************************************************************
 * CONSTANTES
 ********************************************************************/

const bit<16> TYPE_IPV4 = 0x0800;

const bit<8> PROTO_TCP = 6;
const bit<8> PROTO_UDP = 17;

// IP público do NAT = 200.0.0.1
const bit<32> NAT_PUBLIC_IP = 0xC8000001;


/********************************************************************
 * TIPOS
 ********************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;


/********************************************************************
 * HEADERS
 ********************************************************************/

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}


header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}


/*
 * Cabeçalho TCP mínimo.
 *
 * dataOffset = 4 bits
 * reserved   = 3 bits
 * flags      = 9 bits
 *
 * Total = 16 bits
 */
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;

    bit<32> seqNo;
    bit<32> ackNo;

    bit<4>  dataOffset;
    bit<3>  reserved;
    bit<9>  flags;

    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}


header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}


/********************************************************************
 * METADATA
 ********************************************************************/

struct metadata {

    // Portas originais do pacote
    bit<16> srcPort;
    bit<16> dstPort;

    // Tamanho do segmento TCP
    // Calculado no Ingress para ser usado no checksum.
    bit<16> tcpLength;
}


/********************************************************************
 * CONJUNTO DE HEADERS
 ********************************************************************/

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    udp_t      udp;
}


/********************************************************************
 * PARSER
 ********************************************************************/

parser MyParser(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {

    state start {
        transition parse_ethernet;
    }


    state parse_ethernet {

        packet.extract(hdr.ethernet);

        transition select(hdr.ethernet.etherType) {

            TYPE_IPV4: parse_ipv4;

            default: accept;
        }
    }


    state parse_ipv4 {

        packet.extract(hdr.ipv4);

        transition select(hdr.ipv4.protocol) {

            PROTO_TCP: parse_tcp;

            PROTO_UDP: parse_udp;

            // Outros protocolos seguem para o Ingress,
            // onde serão descartados.
            default: accept;
        }
    }


    state parse_tcp {

        packet.extract(hdr.tcp);

        transition accept;
    }


    state parse_udp {

        packet.extract(hdr.udp);

        transition accept;
    }
}


/********************************************************************
 * VERIFICAÇÃO DE CHECKSUM
 ********************************************************************/

control MyVerifyChecksum(
    inout headers hdr,
    inout metadata meta
) {

    apply {
        // Não é necessário verificar aqui para este trabalho.
    }
}


/********************************************************************
 * INGRESS
 ********************************************************************/

control MyIngress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {

    /*
     * Estado dinâmico do NAT (uma "tabela de conexões" em registradores).
     *
     * Índice = porta PÚBLICA (+65536 se UDP, para TCP e UDP terem
     * espaços de portas separados).
     *
     *   nat_owner_ip[porta_publica]   = IP privado dono da porta
     *   nat_owner_port[porta_publica] = porta privada original
     *
     * Serve para as duas direções: na saída reserva/consulta a porta
     * pública; na volta descobre o host/porta privados.
     */
    register<bit<32>>(131072) nat_owner_ip;
    register<bit<16>>(131072) nat_owner_port;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    /* ---------- regras estáticas (ponto extra / port-forward) ---------- */

    action static_out(bit<16> public_port) {
        hdr.ipv4.srcAddr = NAT_PUBLIC_IP;
        if (hdr.tcp.isValid()) { hdr.tcp.srcPort = public_port; }
        if (hdr.udp.isValid()) { hdr.udp.srcPort = public_port; }
    }

    action static_in(ip4Addr_t private_ip, bit<16> private_port) {
        hdr.ipv4.dstAddr = private_ip;
        if (hdr.tcp.isValid()) { hdr.tcp.dstPort = private_port; }
        if (hdr.udp.isValid()) { hdr.udp.dstPort = private_port; }
    }

    table nat_out_static {
        key = {
            hdr.ipv4.srcAddr  : exact;
            meta.srcPort      : exact;
            hdr.ipv4.protocol : exact;
        }
        actions = { static_out; NoAction; }
        size = 64;
        default_action = NoAction();
    }

    table nat_in_static {
        key = {
            meta.dstPort      : exact;
            hdr.ipv4.protocol : exact;
        }
        actions = { static_in; NoAction; }
        size = 64;
        default_action = NoAction();
    }

    table ipv4_lpm {
        key = { hdr.ipv4.dstAddr : lpm; }
        actions = { ipv4_forward; drop; NoAction; }
        size = 1024;
        default_action = drop();
    }

    apply {
        bit<32> base      = 0;
        bit<32> idx       = 0;
        bit<32> owner     = 0;
        bit<16> owner_prv = 0;
        bit<16> newPort   = 0;
        bit<16> alt       = 0;
        bool    ok        = true;

        if (!hdr.ipv4.isValid() || !(hdr.tcp.isValid() || hdr.udp.isValid())) {
            // não-IPv4, ICMP e qualquer outro protocolo: descarta
            drop();
        } else {

            if (hdr.tcp.isValid()) {
                meta.srcPort   = hdr.tcp.srcPort;
                meta.dstPort   = hdr.tcp.dstPort;
                meta.tcpLength = hdr.ipv4.totalLen - 16w20;
                base = 0;
            } else {
                meta.srcPort = hdr.udp.srcPort;
                meta.dstPort = hdr.udp.dstPort;
                base = 65536;
            }

            /* ======================= SAÍDA: 10.0.0.0/24 -> fora ======================= */
            if ((hdr.ipv4.srcAddr & 0xFFFFFF00) == 0x0A000000) {

                if (!nat_out_static.apply().hit) {

                    // 1ª tentativa: preservar a porta de origem
                    idx = base + (bit<32>)meta.srcPort;
                    nat_owner_ip.read(owner, idx);
                    nat_owner_port.read(owner_prv, idx);

                    if (owner == 0 || (owner == hdr.ipv4.srcAddr && owner_prv == meta.srcPort)) {
                        newPort = meta.srcPort;
                    } else {
                        // Conflito (outro host já usa essa porta pública):
                        // usa uma porta alternativa determinística.
                        alt = meta.srcPort ^ 16w0x8000;
                        idx = base + (bit<32>)alt;
                        nat_owner_ip.read(owner, idx);
                        nat_owner_port.read(owner_prv, idx);

                        if (owner == 0 || (owner == hdr.ipv4.srcAddr && owner_prv == meta.srcPort)) {
                            newPort = alt;
                        } else {
                            ok = false;
                        }
                    }

                    if (ok) {
                        // registra/atualiza o mapeamento porta_pública -> (IP, porta) privados
                        nat_owner_ip.write(idx, hdr.ipv4.srcAddr);
                        nat_owner_port.write(idx, meta.srcPort);

                        hdr.ipv4.srcAddr = NAT_PUBLIC_IP;
                        if (hdr.tcp.isValid()) { hdr.tcp.srcPort = newPort; }
                        if (hdr.udp.isValid()) { hdr.udp.srcPort = newPort; }
                    }
                }
            }

            /* ======================= VOLTA: fora -> 200.0.0.1 ======================= */
            else if (hdr.ipv4.dstAddr == NAT_PUBLIC_IP) {

                if (!nat_in_static.apply().hit) {
                    idx = base + (bit<32>)meta.dstPort;
                    nat_owner_ip.read(owner, idx);
                    nat_owner_port.read(owner_prv, idx);

                    if (owner == 0) {
                        ok = false;          // sem mapeamento: descarta
                    } else {
                        hdr.ipv4.dstAddr = owner;
                        if (hdr.tcp.isValid()) { hdr.tcp.dstPort = owner_prv; }
                        if (hdr.udp.isValid()) { hdr.udp.dstPort = owner_prv; }
                    }
                }
            }

            /* Tráfego externo que não é para o NAT: não encaminha */
            else {
                ok = false;
            }

            if (ok) {
                ipv4_lpm.apply();
            } else {
                drop();
            }
        }
    }
}


/********************************************************************
 * EGRESS
 ********************************************************************/

control MyEgress(
    inout headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata
) {

    apply {

    }
}


/********************************************************************
 * CÁLCULO DOS CHECKSUMS
 ********************************************************************/

control MyComputeChecksum(
    inout headers hdr,
    inout metadata meta
) {

    apply {


        /************************************************************
         * CHECKSUM IPv4
         ************************************************************/

        update_checksum(
            hdr.ipv4.isValid(),
            {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            },

            hdr.ipv4.hdrChecksum,

            HashAlgorithm.csum16
        );


        /************************************************************
         * CHECKSUM TCP
         *
         * Inclui pseudo-header IPv4 + header TCP + payload.
         ************************************************************/

        update_checksum_with_payload(
            hdr.tcp.isValid(),
            {
                /*
                 * Pseudo-header IPv4
                 */
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                meta.tcpLength,

                /*
                 * Cabeçalho TCP
                 */
                hdr.tcp.srcPort,
                hdr.tcp.dstPort,
                hdr.tcp.seqNo,
                hdr.tcp.ackNo,
                hdr.tcp.dataOffset,
                hdr.tcp.reserved,
                hdr.tcp.flags,
                hdr.tcp.window,
                hdr.tcp.urgentPtr
            },

            hdr.tcp.checksum,

            HashAlgorithm.csum16
        );


        /************************************************************
         * CHECKSUM UDP
         *
         * Inclui pseudo-header IPv4 + header UDP + payload.
         ************************************************************/

        update_checksum_with_payload(
            hdr.udp.isValid(),
            {
                /*
                 * Pseudo-header IPv4
                 */
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                hdr.udp.length,

                /*
                 * Cabeçalho UDP
                 */
                hdr.udp.srcPort,
                hdr.udp.dstPort,
                hdr.udp.length
            },

            hdr.udp.checksum,

            HashAlgorithm.csum16
        );
    }
}


/********************************************************************
 * DEPARSER
 ********************************************************************/

control MyDeparser(
    packet_out packet,
    in headers hdr
) {

    apply {

        packet.emit(hdr.ethernet);

        packet.emit(hdr.ipv4);

        packet.emit(hdr.tcp);

        packet.emit(hdr.udp);
    }
}


/********************************************************************
 * SWITCH
 ********************************************************************/

V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;
