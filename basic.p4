// SPDX-FileCopyrightText: 2018 Nate Foster
// SPDX-License-Identifier: Apache-2.0
/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
* This program skeleton defines minimal Ethernet and IPv4 headers and    *
* a simple LPM (Longest-Prefix Match) IPv4 forwarding pipeline.          *
* The exercise intentionally leaves TODOs for learners to implement.     *
*************************************************************************/

typedef bit<9>  egressSpec_t;   // Standard BMv2 uses 9 bits for egress_spec
typedef bit<48> macAddr_t;      // Ethernet MAC address
typedef bit<32> ip4Addr_t;      // IPv4 address

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

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  reserved;
    bit<8>  flags;
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

struct metadata {
    bit<16> srcPort;
    bit<16> dstPort;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t         tcp;
    udp_t          udp;
}

/*************************************************************************
*********************** P A R S E R  *************************************
* New to P4? A typical parser does this:
*   start -> parse_ethernet
*   parse_ethernet:
*       if etherType == TYPE_IPV4 -> parse_ipv4
*       else accept
*   parse_ipv4 -> accept
* This skeleton leaves the actual states as a TODO to implement later.   *
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

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
          6: parse_tcp;
          17: parse_udp;
          default: reject;
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

        /* TODO: add parser logic
         * Suggested outline:
         *   1) Extract Ethernet: packet.extract(hdr.ethernet);
         *   2) If hdr.ethernet.etherType == TYPE_IPV4 -> parse IPv4
         *   3) Otherwise -> transition accept
         */
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
* High-level intent:
*   - Do an LPM lookup on IPv4 dstAddr
*   - On hit, call ipv4_forward(next-hop MAC, output port)
*   - Otherwise, drop or NoAction (as configured)                         *
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    /**********************************************************
     * DESCARTA PACOTE
     **********************************************************/
    action drop() {
        mark_to_drop(standard_metadata);
    }


    /**********************************************************
     * ENCAMINHAMENTO IPv4
     **********************************************************/
    action ipv4_forward(macAddr_t dstAddr,
                        egressSpec_t port) {

        standard_metadata.egress_spec = port;

        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;

        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }


    /**********************************************************
     * NAT DE SAÍDA
     *
     * Exemplo:
     *
     * 10.0.0.1:5000
     *        ↓
     * 200.0.0.1:5000
     *
     * ou, se houver conflito:
     *
     * 10.0.0.2:5000
     *        ↓
     * 200.0.0.1:5001
     **********************************************************/
    action nat_out(bit<16> translated_port) {

        // troca o endereço privado pelo IP público do NAT
        hdr.ipv4.srcAddr = NAT_PUBLIC_IP;

        if (hdr.tcp.isValid()) {
            hdr.tcp.srcPort = translated_port;
        }

        if (hdr.udp.isValid()) {
            hdr.udp.srcPort = translated_port;
        }
    }


    /**********************************************************
     * NAT DE RETORNO
     *
     * Exemplo:
     *
     * 200.0.0.2:9001 -> 200.0.0.1:5000
     *
     * vira:
     *
     * 200.0.0.2:9001 -> 10.0.0.1:5000
     **********************************************************/
    action nat_in(ip4Addr_t private_ip,
                  bit<16> private_port) {

        hdr.ipv4.dstAddr = private_ip;

        if (hdr.tcp.isValid()) {
            hdr.tcp.dstPort = private_port;
        }

        if (hdr.udp.isValid()) {
            hdr.udp.dstPort = private_port;
        }
    }


    /**********************************************************
     * TABELA NAT DE SAÍDA
     *
     * Usa a conexão original para descobrir qual porta pública
     * deverá ser utilizada.
     **********************************************************/
    table nat_out_table {

        key = {

            hdr.ipv4.srcAddr : exact;
            hdr.ipv4.dstAddr : exact;

            meta.srcPort : exact;
            meta.dstPort : exact;

            hdr.ipv4.protocol : exact;
        }

        actions = {
            nat_out;
            NoAction;
        }

        size = 1024;

        default_action = NoAction();
    }


    /**********************************************************
     * TABELA NAT DE RETORNO
     *
     * Usa a porta pública para descobrir para qual host
     * privado o pacote deverá voltar.
     **********************************************************/
    table nat_in_table {

        key = {

            hdr.ipv4.srcAddr : exact;

            meta.srcPort : exact;
            meta.dstPort : exact;

            hdr.ipv4.protocol : exact;
        }

        actions = {
            nat_in;
            NoAction;
        }

        size = 1024;

        default_action = NoAction();
    }


    /**********************************************************
     * TABELA DE ENCAMINHAMENTO IPv4
     **********************************************************/
    table ipv4_lpm {

        key = {
            hdr.ipv4.dstAddr : lpm;
        }

        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }

        size = 1024;

        default_action = drop();
    }


    /**********************************************************
     * PROCESSAMENTO
     **********************************************************/
    apply {

        /*
         * O trabalho aceita somente IPv4.
         */

        if (!hdr.ipv4.isValid()) {

            drop();

        }

        /*
         * TCP
         */

        else if (hdr.tcp.isValid()) {

            // guarda as portas originais
            meta.srcPort = hdr.tcp.srcPort;
            meta.dstPort = hdr.tcp.dstPort;


            /*
             * Pacote vindo da rede privada.
             *
             * 10.0.0.0/24
             *
             * Verifica os primeiros 24 bits.
             */

            if ((hdr.ipv4.srcAddr & 0xFFFFFF00) ==
                0x0A000000) {

                nat_out_table.apply();

            }

            /*
             * Pacote vindo da rede pública para o IP do NAT.
             */

            else if (hdr.ipv4.dstAddr == NAT_PUBLIC_IP) {

                nat_in_table.apply();

            }


            /*
             * Depois do NAT, faz o encaminhamento.
             */

            ipv4_lpm.apply();
        }

        /*
         * UDP
         */

        else if (hdr.udp.isValid()) {

            // guarda as portas originais
            meta.srcPort = hdr.udp.srcPort;
            meta.dstPort = hdr.udp.dstPort;


            /*
             * Rede privada -> pública
             */

            if ((hdr.ipv4.srcAddr & 0xFFFFFF00) ==
                0x0A000000) {

                nat_out_table.apply();

            }

            /*
             * Rede pública -> NAT
             */

            else if (hdr.ipv4.dstAddr == NAT_PUBLIC_IP) {

                nat_in_table.apply();

            }


            ipv4_lpm.apply();
        }

        /*
         * Qualquer outro protocolo:
         *
         * ICMP
         * GRE
         * etc.
         */

        else {

            drop();

        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
* Often used for queue marks, mirroring, or post-routing edits.          *
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
* This block shows how to compute IPv4 header checksum when needed.      *
*************************************************************************/

control MyComputeChecksum(inout headers hdr,
                          inout metadata meta) {

    apply {

        /******************************************************
         * IPv4
         ******************************************************/
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


        /******************************************************
         * TCP
         ******************************************************/
        update_checksum_with_payload(
            hdr.tcp.isValid(),
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                hdr.ipv4.totalLen - 20,

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


        /**********
         * UDP
         ********/
        update_checksum_with_payload(
            hdr.udp.isValid(),
            {
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr,
                8w0,
                hdr.ipv4.protocol,
                hdr.udp.length,

                hdr.udp.srcPort,
                hdr.udp.dstPort,
                hdr.udp.length
            },
            hdr.udp.checksum,
            HashAlgorithm.csum16
        );
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
* The deparser serializes headers back onto the packet in order.         *
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        
          packet.emit(hdr.ethernet);
          packet.emit(hdr.ipv4);   // per P4_16 spec, emit appends a header
                                     // only if it is valid; no 'if' needed.

       
         packet.emit(hdr.tcp);
         packet.emit(hdr.udp);
        
        
    }
}

/*************************************************************************
***********************  S W I T C H  ***********************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
