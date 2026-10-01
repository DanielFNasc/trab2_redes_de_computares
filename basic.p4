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


    /****************************************************************
     * DROP
     ****************************************************************/

    action drop() {

        mark_to_drop(standard_metadata);
    }


    /****************************************************************
     * ENCAMINHAMENTO IPv4
     ****************************************************************/

    action ipv4_forward(
        macAddr_t dstAddr,
        egressSpec_t port
    ) {

        standard_metadata.egress_spec = port;

        /*
         * Mantém o comportamento do basic.p4 original.
         */
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;

        hdr.ethernet.dstAddr = dstAddr;

        /*
         * Roteador decrementa TTL.
         */
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }


    /****************************************************************
     * NAT DE SAÍDA
     *
     * Exemplo:
     *
     * 10.0.0.1:5000
     *        |
     *        v
     * 200.0.0.1:5000
     *
     * Se houver conflito, translated_port poderá ser diferente:
     *
     * 10.0.0.2:5000
     *        |
     *        v
     * 200.0.0.1:5001
     ****************************************************************/

    action nat_out(bit<16> translated_port) {

        /*
         * Troca o IP privado pelo IP público do NAT.
         */
        hdr.ipv4.srcAddr = NAT_PUBLIC_IP;


        /*
         * TCP
         */
        if (hdr.tcp.isValid()) {

            hdr.tcp.srcPort = translated_port;
        }


        /*
         * UDP
         */
        if (hdr.udp.isValid()) {

            hdr.udp.srcPort = translated_port;
        }
    }


    /****************************************************************
     * NAT DE RETORNO
     *
     * Exemplo:
     *
     * H3 responde para:
     *
     * 200.0.0.1:5000
     *
     * A tabela descobre:
     *
     * 200.0.0.1:5000
     *        |
     *        v
     * 10.0.0.1:5000
     ****************************************************************/

    action nat_in(
        ip4Addr_t private_ip,
        bit<16> private_port
    ) {

        /*
         * Restaura IP privado de destino.
         */
        hdr.ipv4.dstAddr = private_ip;


        /*
         * Restaura porta TCP.
         */
        if (hdr.tcp.isValid()) {

            hdr.tcp.dstPort = private_port;
        }


        /*
         * Restaura porta UDP.
         */
        if (hdr.udp.isValid()) {

            hdr.udp.dstPort = private_port;
        }
    }


    /****************************************************************
     * TABELA NAT DE SAÍDA
     *
     * Identifica uma conexão pela combinação:
     *
     * IP origem
     * IP destino
     * porta origem
     * porta destino
     * protocolo
     ****************************************************************/

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


    /****************************************************************
     * TABELA NAT DE RETORNO
     *
     * Identifica para qual host privado o pacote deve retornar.
     ****************************************************************/

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


    /****************************************************************
     * TABELA DE ENCAMINHAMENTO IPv4
     ****************************************************************/

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


    /****************************************************************
     * APPLY
     ****************************************************************/

    apply {


        /************************************************************
         * NÃO É IPv4
         *
         * Descarta.
         ************************************************************/

        if (!hdr.ipv4.isValid()) {

            drop();
        }


        /************************************************************
         * TCP
         ************************************************************/

        else if (hdr.tcp.isValid()) {


            /*
             * Guarda as portas ORIGINAIS antes de executar o NAT.
             */
            meta.srcPort = hdr.tcp.srcPort;

            meta.dstPort = hdr.tcp.dstPort;


            /*
             * Calcula tamanho TCP.
             *
             * Para IPv4 sem opções:
             *
             * TCP length = IPv4 totalLen - 20
             *
             * Fazemos a conta aqui porque o BMv2 não permite
             * hdr.ipv4.totalLen - 20 diretamente dentro do
             * update_checksum_with_payload().
             */
            meta.tcpLength = hdr.ipv4.totalLen - 16w20;


            /********************************************************
             * REDE PRIVADA -> REDE EXTERNA
             *
             * Verifica se origem pertence a:
             *
             * 10.0.0.0/24
             ********************************************************/

            if ((hdr.ipv4.srcAddr & 0xFFFFFF00) ==
                0x0A000000) {

                nat_out_table.apply();
            }


            /********************************************************
             * REDE EXTERNA -> NAT
             *
             * Pacote destinado a 200.0.0.1
             ********************************************************/

            else if (hdr.ipv4.dstAddr == NAT_PUBLIC_IP) {

                nat_in_table.apply();
            }


            /********************************************************
             * Encaminhamento após NAT
             ********************************************************/

            ipv4_lpm.apply();
        }


        /************************************************************
         * UDP
         ************************************************************/

        else if (hdr.udp.isValid()) {


            /*
             * Guarda as portas originais.
             */
            meta.srcPort = hdr.udp.srcPort;

            meta.dstPort = hdr.udp.dstPort;


            /********************************************************
             * REDE PRIVADA -> EXTERNA
             ********************************************************/

            if ((hdr.ipv4.srcAddr & 0xFFFFFF00) ==
                0x0A000000) {

                nat_out_table.apply();
            }


            /********************************************************
             * REDE EXTERNA -> NAT
             ********************************************************/

            else if (hdr.ipv4.dstAddr == NAT_PUBLIC_IP) {

                nat_in_table.apply();
            }


            /********************************************************
             * Encaminhamento
             ********************************************************/

            ipv4_lpm.apply();
        }


        /************************************************************
         * OUTROS PROTOCOLOS
         *
         * ICMP, GRE etc.
         *
         * O trabalho exige descarte.
         ************************************************************/

        else {

            drop();
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
