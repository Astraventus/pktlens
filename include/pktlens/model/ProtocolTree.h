#ifndef PKTLENS_PROTOCOLTREE_H
#define PKTLENS_PROTOCOLTREE_H

#include "ProtoId.h"
#include <string>
#include <vector>
#include <cstdint>

namespace pktlens {

    // This struct represents a single field in node.
    // like protocol = TCP, fields = [src_port, st_port etc.]
    // offset is from the start of raw packet in bytes
    // length is length of the field in this raw packet in bytes
    struct Field {
        std::string name;
        std::string value;

        uint16_t offset;
        uint16_t length;
    };

    // Node struct of the ProtocolTree
    struct Node {
        ProtoId protocol;
        std::vector<Field> fields;
        std::vector<Node> children;
    };

    //  Has full decoded structure for one packet;
    //  Built on demand when user selects a packet and discarded afterwards;
    //  Root in practice is Ethernet;
    struct ProtocolTree {
        Node root;

        // Helper function to check whether the tree is empty;
        bool empty() const { return root.fields.empty() && root.children.empty(); }
    };

    // Helper function to streamline creation of fields;
    inline Field make_field(std::string name, std::string value, uint16_t offset, 
                            uint16_t length) {
        Field field;
        field.name = std::move(name);
        field.value = std::move(value);
        field.offset = offset;
        field.length = length;
        return field;
    }

}

#endif