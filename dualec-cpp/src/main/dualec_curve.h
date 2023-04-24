#pragma once
#include "affine_point.h"
#include "elliptic_curve.h"

struct DualEcCurve {
    EllipticCurve curve;
    std::string name;
    AffinePoint P; // this has to be the base G
    AffinePoint Q;
};
