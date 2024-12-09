from mvrepository import MVRepo
from key.rsa import RSAkeyGenerator,RSAkey


if __name__ == "__main__":
    operation = input("Enter the operation [c=create, t=add target, s = out-of-band sign, a=auto sign]:")
    r = None
    if operation in ('s','S'):
        r = MVRepo()
        key = RSAkey().get_signer(pvtkey_file="./keys/secrets/root-f609b4_private.pem")
        r.out_of_band_root_sign(key,"./tufrepo")

    elif operation in ('c','C'):
        r = MVRepo()
        r.set_signer(role='root', private_key="./keys/secrets/root-2ec8ea_private.pem", encryption="rsa")
        #r.set_signer(role='root',private_key="./keys/secrets/root-f609b4_private.pem", encryption="rsa")
        r.set_signer(role='targets', private_key="./keys/secrets/targets-cd1f1e_private.pem", encryption="rsa")
        r.set_signer(role='snapshot', private_key="./keys/secrets/snapshot-ff6286_private.pem", encryption="rsa")
        r.set_signer(role='timestamp', private_key="./keys/secrets/timestamp-761727_private.pem", encryption="rsa")
        r.set_role_threshold("root", 2)
        root2_public = RSAkey().get_public_key_from_file("./keys/root-f609b4_public.pem")
        r.set_out_of_band_publickey(root2_public, "root")
        r.create()

    elif operation in ("t","T"):
        r = MVRepo()
        r.set_signer(role='targets', private_key="./keys/secrets/targets-cd1f1e_private.pem", encryption="rsa")
        r.set_signer(role='snapshot', private_key="./keys/secrets/snapshot-ff6286_private.pem", encryption="rsa")
        r.set_signer(role='timestamp', private_key="./keys/secrets/timestamp-761727_private.pem", encryption="rsa")
        r.add_targets("./tufrepo", [
                                    "/tmp/manifest.1",
                                    "/tmp/manifest.2",
                                    "/tmp/mvl-support-1.0-1.0.0.corei7_64.rpm",
                                    "/tmp/python3-tuf-manifest-0.0.3-3.4.0.corei7_64.rpm",
                                    "/tmp/python3-tuf-manifest-client-0.0.3-3.4.0.corei7_64.rpm",
                                    "/tmp/python3-tuf-manifest-dev-0.0.3-3.4.0.corei7_64.rpm"
                                    ])

    elif operation in ("a", "A"):
        r = MVRepo()
        _r = input("Choose role (s=snapshot | t=timestamp) :")
        _role = "snapshot" if _r in ('s','S') else ("timestamp" if _r in("t","T") else exit())
        _key= input("Enter signing key full path :")
        r.set_signer(role=_role, private_key=_key, encryption="rsa")
        r.auto_sign(_role)
    else:
        pass

    v = r._verify_root_signature()
    print(v)
    print("OK") if v else print("NOT OK")
    exit()
    #
    #else:
    #    print("False")


    #exit()
    r1 = MVRepo()
    #r1.set_signer(role='root', private_key="./keys/secrets/root-2ec8ea_private.pem", encryption="rsa")
    #r1.set_signer(role='root', private_key="./keys/secrets/root-f609b4_private.pem", encryption="rsa")
    r1.set_signer(role='targets', private_key="./keys/secrets/targets-cd1f1e_private.pem", encryption="rsa")
    r1.set_signer(role='snapshot', private_key="./keys/secrets/snapshot-ff6286_private.pem", encryption="rsa")
    r1.set_signer(role='timestamp', private_key="./keys/secrets/timestamp-761727_private.pem", encryption="rsa")
    r1.add_targets("./tufrepo", ["/home/msatpathy/hello.txt"])