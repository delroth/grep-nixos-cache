rule contains_libwebp {
  strings:
    $sig = "no memory during frame initialization."
  condition:
    $sig
}

rule contains_libpng {
  strings:
    $sig = "Copyright (c) 1995-1996 Guy Eric Schalnat, Group 42, Inc."
  condition:
    $sig
}

rule contains_openssl {
  strings:
    $sig = "calling OPENSSL_dir_read(%s)"
  condition:
    $sig
}

rule contains_libressl {
  strings:
    $sig = "peer failed to provide a certificate"
  condition:
    $sig
}

rule contains_zlib {
  strings:
    $sig = "too many length or distance symbols"
  condition:
    $sig
}

rule contains_libjpeg {
  strings:
    $sig = "Missing Huffman code table entry"
  condition:
    $sig
}

rule contains_libcurl {
  strings:
    $sig = "A libcurl function was given a bad argument"
  condition:
    $sig
}
