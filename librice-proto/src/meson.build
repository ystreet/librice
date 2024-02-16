
sources = [
    'lib.rs',
    'candidate.rs',
    'conncheck.rs',
    'gathering.rs',
    'utils.rs',
    'stun/mod.rs',
    'stun/agent.rs',
    'stun/attribute.rs',
    'stun/message.rs',
]

byteorder = dependency('byteorder-rs')
crc = dependency('crc-rs')
md5 = dependency('md-5-rs')
hmac = dependency('hmac-rs')
sha1 = dependency('sha-1-rs')
sha2 = dependency('sha2-rs')
nom = dependency('nom-rs')
rand = dependency('rand-rs')
tracing = dependency('tracing-rs')
# FIXME: proc-macro dep doesn't seem to be forwarded from the tracing dep
tracing_attributes = dependency('tracing-attributes-rs')

librice_proto = static_library('librice_proto',
    sources,
    dependencies: [byteorder, crc, md5, hmac, sha1, sha2, nom, rand, tracing, tracing_attributes],
    rust_dependency_map: {'md_5': 'md5', 'sha_1': 'sha1'}
)

librice_proto_dep = declare_dependency(link_with: librice_proto, dependencies: [tracing_attributes])
