project('libkmip', 'c',
        version : '0.1',
        meson_version: '>=0.59.0',
        default_options: [
            'warning_level=3',
            'werror=true',
           ])

# Add c compiler arguments
cc = meson.get_compiler('c')
# -Wpedantic, -Wextra comes by default with warning level
add_project_arguments(
  cc.get_supported_arguments([
  '-Wcast-align',
  '-Wconversion',
  '-Wformat=2',
  '-Wold-style-cast',
  '-Woverloaded-virtual',
  '-Wno-attributes',
  '-Wno-variadic-macros',
  '-Wno-deprecated-declarations',
  '-Wno-sign-conversion', 
  '-Wno-error=sign-conversion',
  '-Wno-unused',
  '-Wno-error=unused',
  '-Wno-conversion',
  '-Wno-error=conversion',
  ]),
  language: 'c'
)

kmip_library_version = '1.0.1'
kmip_library_name = 'kmip'

c_args = []
link_args = []
if get_option('with-wolfssl')
    wolfssl_dep = dependency('wolfssl')
    ssl_dep = wolfssl_dep
    crypto_dep = wolfssl_dep
    c_args += '-DENABLE_WOLFSSL'
    c_args += '-DOPENSSL_ALL '
else
    openssl_dep = dependency('openssl').as_system('system')
    crypto_dep = dependency('libcrypto', version: '> 1.0.2g').as_system('system')
    ssl_dep = [ openssl_dep, crypto_dep ]
endif

inc = include_directories('include')
install_headers(
  'include/kmip.h', 
  'include/kmip_bio.h', 
  'include/kmip_io.h', 
  'include/kmip_memset.h',
  install_dir: join_paths(get_option('includedir'), 'libkmip')
)

# Add the build directory's libkmip directory to the include path
# build_inc = join_paths(get_option('includedir'), 'libkmip')
# include_directories(build_inc)

sources_kmip = [
    'src/kmip.c', 
    'src/kmip_bio.c', 
    'src/kmip_io.c', 
    'src/kmip_memset.c'
]

libkmip = library(
    kmip_library_name,
    include_directories: [inc],
    dependencies: ssl_dep,
    c_args: c_args,
    install: true,
    install_dir: get_option('libdir'),
    version: kmip_library_version,
    sources: sources_kmip
)

libkmip_dep = declare_dependency(
    include_directories: inc,
    link_with: libkmip
)

import('pkgconfig').generate(
    libkmip,
    name: 'libkmip',
    version: kmip_library_version,
    description: 'OpenKMIP libkmip',
)
