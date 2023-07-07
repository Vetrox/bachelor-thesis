#include "affine_point.h"
#include "dualec.h"
#include "dualec_curve.h"
#include "elliptic_curve.h"
#include "forward.h"
#include "jacobi_point.h"
#include <givaro/random-integer.h>
#include <ios>

static BigInt TEST_SIZE = 10'000;


int main(int argc, char const** argv)
{
    if (argc > 1)
        TEST_SIZE = BigInt(argv[1]);
    auto const& dec_curve = argc > 2 ? DEC::pick_curve(BigInt(argv[2])) : DEC::P521;
    std::cout << "Using the following curve: " + dec_curve.curve.to_string() << std::endl;
    auto gen = dec_curve.P;
#ifdef USE_SLOW_EC
    AffinePoint out;
#else
    auto out = JacobiPoint(Zp(dec_curve.curve.prime()));
#endif

    Givaro::RandomIntegerIterator<> r (Zp(dec_curve.order_of_p), 1, dec_curve.order_of_p);
    bool work = true;
    for (BigInt i = 0; i < TEST_SIZE; ++i) {
        BigInt a = 0;
        while (a == 0 || a == 1)
            a = r.random();
        dec_curve.curve.scalar(out, gen, a);
        std::cout << bigint_hex(out.x()) << "\n";
        // work ^= out.y() > 0;
    }

    return work;
}
