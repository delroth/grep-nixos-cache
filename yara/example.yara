rule contains_libwebp {
  strings:
    $sig = "no memory during frame initialization."
  condition:
    $sig
}

rule contains_libpng {
  strings:
    $sig = "Gray color space not permitted on RGB PNG"
  condition:
    $sig
}

rule contains_libssl {
  strings:
    $sig = "calling OPENSSL_dir_read(%s)"
  condition:
    $sig
}
