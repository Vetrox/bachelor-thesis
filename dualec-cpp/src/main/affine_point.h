#pragma once

#include "forward.h"

class AffinePoint {
public:
    AffinePoint() : m_identity(true) {}
    AffinePoint(Element x, Element y)
        : m_identity(false),
        m_x(x),
        m_y(y) {}

    bool identity() {
        return m_identity;
    }

    void setX(Element x) {
        m_x = x;
    }
    void setY(Element y) {
        m_y = y;
    }

    Element x() {
        return m_x;
    }

    Element y() {
        return m_y;
    }

    bool operator==(const AffinePoint& other) const {
        return (m_identity && other.m_identity) || (!m_identity && !other.m_identity && m_x == other.m_x && m_y == other.m_y);
    }

    std::string to_string() {
        if (m_identity) {
            return "Infinity";
        } else {
            return "(" + std::string(this->m_x) + ", " + std::string(this->m_y) + ")";
        }
    }

private:
    bool m_identity{ false };
    Element m_x;
    Element m_y;
};
