#pragma once
#include "affine_point.h"
#include "elliptic_curve.h"

struct DualEcCurve {
    std::string name;
    EllipticCurve curve;
    AffinePoint P; // this has to be the base G
    AffinePoint Q;

    std::string to_string() const
    {
        return "DualEcCurve(name = " 
            + name
            + "curve = " + curve.to_string()
            + "P = " + P.to_string()
            + "Q = " + Q.to_string() + ")";
    }
};

static const DualEcCurve Dual_EC_P256{
    .name = "P-256",
    .curve = EllipticCurve(
            BigInt("115792089210356248762697446949407573530086143415290314195533631308867097853951"),
            BigInt("115792089210356248762697446949407573529996955224135760342422259061068512044369"),
            BigInt("-3"), // a
            BigInt("41058363725152142129326129780047268409114441015993725554835256314039467401291")), // b
    .P = AffinePoint( // Base point for P-256 and also P
            BigInt("48439561293906451759052585252797914202762949526041747995844080717082404635286"),
            BigInt("36134250956749795798585127919587881956611106672985015071877198253568414405109")),
    .Q = AffinePoint(
            BigInt("91120319633256209954638481795610364441930342474826146651283703640232629993874"),
            BigInt("80764272623998874743522585409326200078679332703816718187804498579075161456710"))};
