defmodule COSETest.Sign1 do
  use ExUnit.Case
  doctest COSE
  alias COSE.{Keys, Messages}
  alias Messages.{Sign1}

  describe "sign1 message" do
    setup do
      key = Keys.OKP.generate(:sig)

      d = Base.decode16!("8437C5D1CB4DE744B33B23A943644268A2CC0F11AF66953F74BAB8B395AFCC21")
      x = Base.decode16!("0D89C5C34501D85E9D23EDBFF932AA85B660100C3534D98F8A0722C992D8B324")
      key = Map.put(key, :d, d) |> Map.put(:x, x)

      msg = Sign1.build("content to sign", %{alg: :eddsa})
      {:ok, %{key: key, msg: msg}}
    end

    test "sign", %{key: key, msg: msg} do
      msg = Sign1.sign(msg, key)
      assert Sign1.verify(msg, key)

      # alter signature
      <<_::binary-size(3)>> <> tmp = msg.signature.value
      altered_signature = "aaa" <> tmp
      altered_msg = Map.put(msg, :signature, COSE.tag_as_byte(altered_signature))
      refute Sign1.verify(altered_msg, key)
    end

    test "encode", %{key: key, msg: msg} do
      encoded_msg = Sign1.sign_encode(msg, key)
      verified_msg = Messages.Sign1.verify_decode(encoded_msg, key)
      assert verified_msg == Sign1.sign(msg, key)
    end

    test "round trip valid es256" do
      {public_key, private_key} = :crypto.generate_key(:ecdh, :secp256r1)
      msg = Sign1.build("content to sign", %{alg: :es256})
      encoded_msg = Sign1.sign_encode(:es256, msg, private_key)
      assert Messages.Sign1.verify_decode(:es256, encoded_msg, public_key)
    end

    # Precooked message taken from cose repo https://github.com/cose-wg/Examples/blob/master/ecdsa-examples/ecdsa-sig-01.json
    test "precooked es256 message produces expected to be signed bytes" do
      msg = Sign1.build("This is the content.", %{alg: :es256, ctyp: 0})
      encoded_tbs_bytes = CBOR.encode(COSE.Messages.Sign1.sig_structure(msg, <<>>))
      assert encoded_tbs_bytes == Base.decode16!("846A5369676E61747572653145A2012603004054546869732069732074686520636F6E74656E742E")
    end

    test "verify precooked es256 message passes verification" do
      encoded_message = Base.decode16!("D28445A201260300A10442313154546869732069732074686520636F6E74656E742E58406520BBAF2081D7E0ED0F95F76EB0733D667005F7467CEC4B87B9381A6BA1EDE8E00DF29F32A37230F39A842A54821FDD223092819D7728EFB9D3A0080B75380B")
      private_key_hex = "V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM="
      private_key_bytes = Base.decode64!(private_key_hex, case: :lower)
      {public_key, _} = :crypto.generate_key(:ecdh, :secp256r1, private_key_bytes)
      assert Messages.Sign1.verify_decode(:es256, encoded_message, public_key)
    end

    test "wrong public key fails es256 message verification" do
      {_, private_key} = :crypto.generate_key(:ecdh, :secp256r1)
      msg = Sign1.build("content to sign", %{alg: :es256})
      encoded_msg = Sign1.sign_encode(:es256, msg, private_key)
      {wrong_public_key, _} = :crypto.generate_key(:ecdh, :secp256r1)
      refute Messages.Sign1.verify_decode(:es256, encoded_msg, wrong_public_key)
    end
  end
end
