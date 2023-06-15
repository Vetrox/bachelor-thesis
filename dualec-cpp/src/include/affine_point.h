#pragma once

#include "forward.h"

class AffinePoint {
public:
    AffinePoint()
        : m_identity(true)
    {
    }
    AffinePoint(Element x, Element y)
        : m_identity(false)
        , m_x(x)
        , m_y(y)
    {
    }

    bool is_identity() const
    {
        return m_identity;
    }

    void setIdentity(bool identity)
    {
        m_identity = identity;
    }

    void setX(Element x)
    {
        m_x = x;
    }
    void setY(Element y)
    {
        m_y = y;
    }

    Element x() const
    {
        return m_x;
    }

    Element y() const
    {
        return m_y;
    }

    bool operator==(AffinePoint const& other) const
    {
        return (m_identity && other.m_identity) || (!m_identity && !other.m_identity && m_x == other.m_x && m_y == other.m_y);
    }

    std::string to_string() const
    {
        if (m_identity) {
            return "Point(Infinity)";
        } else {
            return "Point(" + bigint_hex(m_x) + ", " + bigint_hex(m_y) + ")";
        }
    }

private:
    bool m_identity { false };
    Element m_x;
    Element m_y;
};
