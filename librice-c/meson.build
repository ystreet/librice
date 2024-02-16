project('librice-c', 'c', 'rust',
  version : '0.0.1',
  meson_version : '>= 1.3',
  default_options : ['buildtype=debugoptimized',
  'rust_std=2021'])

librice_version = '>= @0@'.format(meson.project_version())

pkgconfig = import('pkgconfig')
python3 = import('python').find_installation()
rustmod = import('rust')

cbindgen = find_program('cbindgen')

#librice_header = custom_target(
#    command: [cbindgen, '.', '@OUTPUT@'],
#    input: 'librice.rs',
#    output: 'librice.h',
#    install: true,
#    install_dir: get_option('includedir') / 'librice',
#)

librice_proto_dep = subproject('librice-proto').get_variable('librice_proto_dep')

library('librice-c',
    'librice.rs',
    dependencies: librice_proto_dep,
    rust_abi: 'c',
    install: true,
    install_dir: get_option('libdir'),
)
