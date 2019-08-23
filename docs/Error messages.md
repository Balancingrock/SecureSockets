# Error Messages

OpenSSL will tend to throw error messages of the kind:

__4308471808:error:14094410: SSL routines:ssl3_read_bytes:sslv3 alert handshake failure:ssl/record/rec_layer_s3.c:1362:SSL alert number 40__

The first time I saw this, I thought WTF? But it is not as bad as it may seem. In fact, I now tend to look at the last number first (_40_ in the above case). Then I use the following enum definition:

~~~~
enum {
          close_notify(0),
          unexpected_message(10),
          bad_record_mac(20),
          decryption_failed_RESERVED(21),
          record_overflow(22),
          decompression_failure_RESERVED(30),
          handshake_failure(40),
          no_certificate_RESERVED(41),
          bad_certificate(42),
          unsupported_certificate(43),
          certificate_revoked(44),
          certificate_expired(45),
          certificate_unknown(46),
          illegal_parameter(47),
          unknown_ca(48),
          access_denied(49),
          decode_error(50),
          decrypt_error(51),
          export_restriction_RESERVED(60),
          protocol_version(70),
          insufficient_security(71),
          internal_error(80),
          inappropriate_fallback(86),
          user_canceled(90),
          no_renegotiation_RESERVED(100),
          missing_extension(109),
          unsupported_extension(110),
          certificate_unobtainable_RESERVED(111),
          unrecognized_name(112),
          bad_certificate_status_response(113),
          bad_certificate_hash_value_RESERVED(114),
          unknown_psk_identity(115),
          certificate_required(116),
          no_application_protocol(120),
          (255)
} AlertDescription;
~~~~

And look up the exact string for the given number (_handshake\_failure_ in the above case).

Next I open the document [The Transport Layer Security (TLS) Protocol Version 1.3](https://tools.ietf.org/html/rfc8446) (which also contains the above enum definition) and do a search for _handshake\_failure_. This will usually give a few hits, and I look at each one until I find the one that seems to fit my situation.

Up to now, this approach has always given me a solution.