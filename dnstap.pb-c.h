/* Generated by the protocol buffer compiler.  DO NOT EDIT! */
/* Generated from: dnstap.proto */

#ifndef PROTOBUF_C_dnstap_2eproto__INCLUDED
#define PROTOBUF_C_dnstap_2eproto__INCLUDED

#include <protobuf-c/protobuf-c.h>

PROTOBUF_C__BEGIN_DECLS

#if PROTOBUF_C_VERSION_NUMBER < 1000000
# error This file was generated by a newer version of protoc-c which is incompatible with your libprotobuf-c headers. Please update your headers.
#elif 1000002 < PROTOBUF_C_MIN_COMPILER_VERSION
# error This file was generated by an older version of protoc-c which is incompatible with your libprotobuf-c headers. Please regenerate this file with a newer version of protoc-c.
#endif


typedef struct _Dnstap__Dnstap Dnstap__Dnstap;
typedef struct _Dnstap__Message Dnstap__Message;


/* --- enums --- */

typedef enum _Dnstap__Dnstap__Type {
  DNSTAP__DNSTAP__TYPE__MESSAGE = 1
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(DNSTAP__DNSTAP__TYPE)
} Dnstap__Dnstap__Type;
typedef enum _Dnstap__Message__Type {
  DNSTAP__MESSAGE__TYPE__AUTH_QUERY = 1,
  DNSTAP__MESSAGE__TYPE__AUTH_RESPONSE = 2,
  DNSTAP__MESSAGE__TYPE__RESOLVER_QUERY = 3,
  DNSTAP__MESSAGE__TYPE__RESOLVER_RESPONSE = 4,
  DNSTAP__MESSAGE__TYPE__CLIENT_QUERY = 5,
  DNSTAP__MESSAGE__TYPE__CLIENT_RESPONSE = 6,
  DNSTAP__MESSAGE__TYPE__FORWARDER_QUERY = 7,
  DNSTAP__MESSAGE__TYPE__FORWARDER_RESPONSE = 8,
  DNSTAP__MESSAGE__TYPE__STUB_QUERY = 9,
  DNSTAP__MESSAGE__TYPE__STUB_RESPONSE = 10,
  DNSTAP__MESSAGE__TYPE__TOOL_QUERY = 11,
  DNSTAP__MESSAGE__TYPE__TOOL_RESPONSE = 12
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(DNSTAP__MESSAGE__TYPE)
} Dnstap__Message__Type;
typedef enum _Dnstap__SocketFamily {
  DNSTAP__SOCKET_FAMILY__INET = 1,
  DNSTAP__SOCKET_FAMILY__INET6 = 2
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(DNSTAP__SOCKET_FAMILY)
} Dnstap__SocketFamily;
typedef enum _Dnstap__SocketProtocol {
  DNSTAP__SOCKET_PROTOCOL__UDP = 1,
  DNSTAP__SOCKET_PROTOCOL__TCP = 2
    PROTOBUF_C__FORCE_ENUM_TO_BE_INT_SIZE(DNSTAP__SOCKET_PROTOCOL)
} Dnstap__SocketProtocol;

/* --- messages --- */

struct  _Dnstap__Dnstap
{
  ProtobufCMessage base;
  protobuf_c_boolean has_identity;
  ProtobufCBinaryData identity;
  protobuf_c_boolean has_version;
  ProtobufCBinaryData version;
  protobuf_c_boolean has_extra;
  ProtobufCBinaryData extra;
  Dnstap__Dnstap__Type type;
  Dnstap__Message *message;
};
#define DNSTAP__DNSTAP__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&dnstap__dnstap__descriptor) \
    , 0,{0,NULL}, 0,{0,NULL}, 0,{0,NULL}, 0, NULL }


struct  _Dnstap__Message
{
  ProtobufCMessage base;
  Dnstap__Message__Type type;
  protobuf_c_boolean has_socket_family;
  Dnstap__SocketFamily socket_family;
  protobuf_c_boolean has_socket_protocol;
  Dnstap__SocketProtocol socket_protocol;
  protobuf_c_boolean has_query_address;
  ProtobufCBinaryData query_address;
  protobuf_c_boolean has_response_address;
  ProtobufCBinaryData response_address;
  protobuf_c_boolean has_query_port;
  uint32_t query_port;
  protobuf_c_boolean has_response_port;
  uint32_t response_port;
  protobuf_c_boolean has_query_time_sec;
  uint64_t query_time_sec;
  protobuf_c_boolean has_query_time_nsec;
  uint32_t query_time_nsec;
  protobuf_c_boolean has_query_message;
  ProtobufCBinaryData query_message;
  protobuf_c_boolean has_query_zone;
  ProtobufCBinaryData query_zone;
  protobuf_c_boolean has_response_time_sec;
  uint64_t response_time_sec;
  protobuf_c_boolean has_response_time_nsec;
  uint32_t response_time_nsec;
  protobuf_c_boolean has_response_message;
  ProtobufCBinaryData response_message;
};
#define DNSTAP__MESSAGE__INIT \
 { PROTOBUF_C_MESSAGE_INIT (&dnstap__message__descriptor) \
    , 0, 0,0, 0,0, 0,{0,NULL}, 0,{0,NULL}, 0,0, 0,0, 0,0, 0,0, 0,{0,NULL}, 0,{0,NULL}, 0,0, 0,0, 0,{0,NULL} }


/* Dnstap__Dnstap methods */
void   dnstap__dnstap__init
                     (Dnstap__Dnstap         *message);
size_t dnstap__dnstap__get_packed_size
                     (const Dnstap__Dnstap   *message);
size_t dnstap__dnstap__pack
                     (const Dnstap__Dnstap   *message,
                      uint8_t             *out);
size_t dnstap__dnstap__pack_to_buffer
                     (const Dnstap__Dnstap   *message,
                      ProtobufCBuffer     *buffer);
Dnstap__Dnstap *
       dnstap__dnstap__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   dnstap__dnstap__free_unpacked
                     (Dnstap__Dnstap *message,
                      ProtobufCAllocator *allocator);
/* Dnstap__Message methods */
void   dnstap__message__init
                     (Dnstap__Message         *message);
size_t dnstap__message__get_packed_size
                     (const Dnstap__Message   *message);
size_t dnstap__message__pack
                     (const Dnstap__Message   *message,
                      uint8_t             *out);
size_t dnstap__message__pack_to_buffer
                     (const Dnstap__Message   *message,
                      ProtobufCBuffer     *buffer);
Dnstap__Message *
       dnstap__message__unpack
                     (ProtobufCAllocator  *allocator,
                      size_t               len,
                      const uint8_t       *data);
void   dnstap__message__free_unpacked
                     (Dnstap__Message *message,
                      ProtobufCAllocator *allocator);
/* --- per-message closures --- */

typedef void (*Dnstap__Dnstap_Closure)
                 (const Dnstap__Dnstap *message,
                  void *closure_data);
typedef void (*Dnstap__Message_Closure)
                 (const Dnstap__Message *message,
                  void *closure_data);

/* --- services --- */


/* --- descriptors --- */

extern const ProtobufCEnumDescriptor    dnstap__socket_family__descriptor;
extern const ProtobufCEnumDescriptor    dnstap__socket_protocol__descriptor;
extern const ProtobufCMessageDescriptor dnstap__dnstap__descriptor;
extern const ProtobufCEnumDescriptor    dnstap__dnstap__type__descriptor;
extern const ProtobufCMessageDescriptor dnstap__message__descriptor;
extern const ProtobufCEnumDescriptor    dnstap__message__type__descriptor;

PROTOBUF_C__END_DECLS


#endif  /* PROTOBUF_C_dnstap_2eproto__INCLUDED */
