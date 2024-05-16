defmodule COSE.Keys.Symmetric do
  defstruct [:kty, :kid, :alg, :key_ops, :base_iv, :k]
end

defmodule ECDSASignature do
  require Record

  Record.defrecord(
    :ecdsa_signature,
    :"ECDSA-Sig-Value",
    Record.extract(:"ECDSA-Sig-Value", from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  def new(r, s) when is_integer(r) and is_integer(s) do
    ecdsa_signature(r: r, s: s)
  end

  def new(raw) when is_binary(raw) do
    size = raw |> byte_size() |> div(2)
    <<r::size(size)-unit(8), s::size(size)-unit(8)>> = raw
    new(r, s)
  end

  def to_der(ecdsa_signature() = signature) do
    :public_key.der_encode(:"ECDSA-Sig-Value", signature)
  end
end

defmodule COSE.Keys.OKP do
  defstruct [:kty, :kid, :alg, :key_ops, :base_iv, :crv, :x, :d]

  def generate(:enc) do
    {x, d} = :crypto.generate_key(:eddh, :x25519)

    %__MODULE__{
      kty: :okp,
      crv: :x25519,
      x: x,
      d: d
    }
  end

  def generate(:sig) do
    {x, d} = :crypto.generate_key(:eddsa, :ed25519)

    %__MODULE__{
      kty: :okp,
      crv: :ed25519,
      x: x,
      d: d
    }
  end

  def sign(to_be_signed, key) do
    :crypto.sign(:eddsa, :sha256, to_be_signed, [key.d, :ed25519])
    |> COSE.tag_as_byte()
  end

  def verify(to_be_verified, %CBOR.Tag{tag: :bytes, value: signature}, ver_key) do
    :crypto.verify(:eddsa, :sha256, to_be_verified, signature, [ver_key.x, :ed25519])
  end
end

defmodule COSE.Keys.ECDSA do
  def sign(:es256, to_be_signed_bytes, private_key) do
    :crypto.sign(:ecdsa, :sha256, to_be_signed_bytes, [private_key, :secp256r1])
    |> encode_der_as_cose()
    |> COSE.tag_as_byte()
  end

  def verify(:es256, to_be_verified_bytes, %CBOR.Tag{tag: :bytes, value: cose_encoded_signature}, public_key) do
    signature_der_bytes = ECDSASignature.new(cose_encoded_signature) |> ECDSASignature.to_der()
    :crypto.verify(:ecdsa, :sha256, to_be_verified_bytes, signature_der_bytes, [public_key, :secp256r1])
  end

  defp encode_der_as_cose(der_signature) do
    # The DER signature is a sequence of two integers, r and s, each of which is
    # encoded as a signed big-endian integer. The COSE signature is a CBOR array
    # of two integers, r and s, each of which is encoded as a positive big-endian
    # integer.
    {:"ECDSA-Sig-Value", r, s} = :public_key.der_decode(:"ECDSA-Sig-Value", der_signature)
    # Convert the integers r and s into big endian binaries
    r_bytes = :binary.encode_unsigned(r, :big)
    s_bytes = :binary.encode_unsigned(s, :big)
    # make both of these the same length by padding the shorter one with leading zeros
    r_bytes = pad_leading(r_bytes, byte_size(s_bytes) - byte_size(r_bytes))
    s_bytes = pad_leading(s_bytes, byte_size(r_bytes) - byte_size(s_bytes))
    # concatenate the two integers
    r_bytes <> s_bytes
  end

  defp pad_leading(binary, size) when is_binary(binary) do
    padding_size = max(size - byte_size(binary), 0)
    padding = String.duplicate(<<0>>, padding_size)
    padding <> binary
  end
end
