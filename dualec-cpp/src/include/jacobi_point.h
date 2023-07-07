#pragma once

#include "affine_point.h"
#include "forward.h"
#include <optional>

class JacobiPoint : public AffinePoint {
public:
    JacobiPoint(Zp field)
        : JacobiPoint(1, 1, 0, field)
    {
    }
    JacobiPoint(Element const& x, Element const& y, Element const& z, Zp field)
        : m_field(field)
    {
        m_field.init(m_X, x);
        m_field.init(m_Y, y);
        m_field.init(m_Z, z);
    }

    JacobiPoint(Element const& x, Element const& y, Zp field)
        : JacobiPoint(x, y, 1, field)
    {
    }

    Element x() const override
    {
        if (!m_cache_affine_x.has_value()) {
            Element i;
            if (is_identity()) {
                std::cout << "used x at infinity" << std::endl;
                abort(); // fast optimization accessor shouldn't be called with infinity
            }
            if (jacobi_z() == 1)
                i = jacobi_x();
            else
                m_field.mul(i, m_X, z_sq_inv());
            const_cast<JacobiPoint*>(this)->m_cache_affine_x.emplace(std::move(i));
        }
        return m_cache_affine_x.value();
    }

    Element y() const override
    {
        if (!m_cache_affine_y.has_value()) {
            Element i;
            if (is_identity())
                abort(); // fast optimization accessor shouldn't be called with infinity
            if (jacobi_z() == 1)
                i = jacobi_y();
            else
                m_field.mul(i, m_Y, z_qube_inv());
            const_cast<JacobiPoint*>(this)->m_cache_affine_y.emplace(std::move(i));
        }
        return m_cache_affine_y.value();
    }

    Element const& jacobi_x() const
    {
        return m_X;
    }

    Element const& jacobi_y() const
    {
        return m_Y;
    }

    Element const& jacobi_z() const
    {
        return m_Z;
    }

    std::string to_string() const
    {
        return "(" + bigint_hex(jacobi_x()) + ":" + bigint_hex(jacobi_y()) + ":" + bigint_hex(jacobi_z()) + ")";
    }

    bool is_identity() const override
    {
        return m_Z == 0;
    }

    /*void negate()
    {
        m_field.negin(m_Y);
    }*/

    /*
    AffinePoint to_affine() const
    {
        if (is_identity())
            return AffinePoint();
        return AffinePoint(affine_x(), affine_y());
    }*/

private:
    Element z_qube_inv() const {
        if (!m_cache_z_qube_inv.has_value()) {
            Element z_tmp = z_sq();
            m_field.mulin(z_tmp, m_Z);
            m_field.invin(z_tmp);
            const_cast<JacobiPoint*>(this)->m_cache_z_qube_inv.emplace(std::move(z_tmp));
        }
        return m_cache_z_qube_inv.value();
    }

    Element z_sq_inv() const {
        if (!m_cache_z_sq_inv.has_value()) {
            Element tmp = z_sq();
            m_field.invin(tmp);
            const_cast<JacobiPoint*>(this)->m_cache_z_sq_inv.emplace(std::move(tmp));
        }
        return m_cache_z_sq_inv.value();
    }

    Element z_sq() const {
        if (!m_cache_z_sq.has_value()) {
            Element z_tmp;
            m_field.mul(z_tmp, m_Z, m_Z);
            const_cast<JacobiPoint*>(this)->m_cache_z_sq.emplace(std::move(z_tmp));
        }
        return m_cache_z_sq.value();
    }


    /* c = 2, d = 3. a (in the elliptic curve) = -3 */
    Element m_X;
    Element m_Y;
    Element m_Z;

    std::optional<Element> m_cache_affine_x;
    std::optional<Element> m_cache_affine_y;
    std::optional<Element> m_cache_z_sq;
    std::optional<Element> m_cache_z_sq_inv;
    std::optional<Element> m_cache_z_qube_inv;

    Zp m_field;
};
