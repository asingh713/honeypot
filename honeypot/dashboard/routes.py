"""Dashboard routes: summary, event log, map, and JSON API endpoints."""

from __future__ import annotations

from flask import Blueprint, current_app, jsonify, render_template, request

bp = Blueprint("dashboard", __name__)


def _db():
    return current_app.config["DB"]


@bp.route("/")
def index():
    stats = _db().get_stats()
    return render_template("index.html", stats=stats)


@bp.route("/events")
def events():
    page     = int(request.args.get("page", 1))
    service  = request.args.get("service") or None
    src_ip   = request.args.get("ip") or None
    since    = request.args.get("since") or None
    per_page = 50

    rows  = _db().get_events(service=service, src_ip=src_ip, since=since, page=page, per_page=per_page)
    total = _db().count_events(service=service, src_ip=src_ip, since=since)
    pages = max(1, (total + per_page - 1) // per_page)

    return render_template("events.html",
                           events=rows, page=page, pages=pages,
                           service=service, ip=src_ip, since=since)


@bp.route("/map")
def map_view():
    return render_template("map.html")


# --- JSON API ---

@bp.route("/api/stats")
def api_stats():
    return jsonify(_db().get_stats())


@bp.route("/api/events")
def api_events():
    page    = int(request.args.get("page", 1))
    service = request.args.get("service") or None
    src_ip  = request.args.get("ip") or None
    since   = request.args.get("since") or None
    rows    = _db().get_events(service=service, src_ip=src_ip, since=since, page=page)
    return jsonify(rows)


@bp.route("/api/geo-points")
def api_geo_points():
    points = _db().get_geo_points()
    features = []
    for p in points:
        if p["lat"] is None or p["lon"] is None:
            continue
        features.append({
            "type": "Feature",
            "geometry": {"type": "Point", "coordinates": [p["lon"], p["lat"]]},
            "properties": {
                "ip":           p["src_ip"],
                "city":         p.get("city"),
                "country":      p.get("country"),
                "isp":          p.get("isp"),
                "attack_count": p["attack_count"],
            },
        })
    return jsonify({"type": "FeatureCollection", "features": features})
