#pragma once
#include "elliptic_curve.h"
#include "affine_point.h"

struct DualEcCurve {
    EllipticCurve curve;
    std::string name;
    AffinePoint P; // this has to be the base G
    AffinePoint Q;
};
