from datetime import datetime, timezone
from hashlib import sha256
from typing import Any
from urllib.parse import urlparse

from core.database import graph_edges_collection, graph_nodes_collection


def create_entity_id(entity_type: str, value: str) -> str:
    digest = sha256(value.lower().strip().encode("utf-8")).hexdigest()[:16]
    return f"{entity_type}_{digest}"


async def index_email_graph_entities(
    email_id: str,
    parsed_email: dict[str, Any],
    urls_data: dict[str, Any],
    relay_analysis: dict[str, Any],
) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    now = datetime.now(timezone.utc)

    # Email root node
    email_node_id = f"email_{email_id}"
    nodes.append({
        "_id": email_node_id,
        "entity_type": "email",
        "value": email_id,
        "label": parsed_email.get("filename", "email.eml"),
        "created_at": now,
    })

    # Sender address and domain
    senders = (parsed_email.get("headers") or {}).get("sender") or []
    from_addr = senders[0] if senders else None
    if from_addr:
        sender_node_id = create_entity_id("sender", from_addr)
        nodes.append({
            "_id": sender_node_id,
            "entity_type": "sender",
            "value": from_addr.lower().strip(),
            "label": from_addr,
            "created_at": now,
        })
        edges.append({
            "_id": f"{email_node_id}_sent_by_{sender_node_id}",
            "source": email_node_id,
            "target": sender_node_id,
            "relation": "SENT_FROM",
            "created_at": now,
        })

        if "@" in from_addr:
            domain = from_addr.split("@", 1)[1].lower().strip()
            domain_node_id = create_entity_id("domain", domain)
            nodes.append({
                "_id": domain_node_id,
                "entity_type": "domain",
                "value": domain,
                "label": domain,
                "created_at": now,
            })
            edges.append({
                "_id": f"{sender_node_id}_domain_{domain_node_id}",
                "source": sender_node_id,
                "target": domain_node_id,
                "relation": "BELONGS_TO_DOMAIN",
                "created_at": now,
            })

    # URLs
    all_urls = urls_data.get("all_urls") or []
    for u in all_urls[:30]:
        url_node_id = create_entity_id("url", u)
        nodes.append({
            "_id": url_node_id,
            "entity_type": "url",
            "value": u,
            "label": u[:60],
            "created_at": now,
        })
        edges.append({
            "_id": f"{email_node_id}_url_{url_node_id}",
            "source": email_node_id,
            "target": url_node_id,
            "relation": "CONTAINS_URL",
            "created_at": now,
        })

        try:
            parsed_u = urlparse(u)
            host = parsed_u.netloc.split(":")[0].lower().strip()
            if host:
                host_node_id = create_entity_id("domain", host)
                nodes.append({
                    "_id": host_node_id,
                    "entity_type": "domain",
                    "value": host,
                    "label": host,
                    "created_at": now,
                })
                edges.append({
                    "_id": f"{url_node_id}_host_{host_node_id}",
                    "source": url_node_id,
                    "target": host_node_id,
                    "relation": "HOSTED_ON",
                    "created_at": now,
                })
        except Exception:
            pass

    # Relays
    primary_origin = relay_analysis.get("primary_origin")
    if primary_origin and primary_origin.get("ip"):
        origin_ip = primary_origin["ip"]
        ip_node_id = create_entity_id("ip", origin_ip)
        nodes.append({
            "_id": ip_node_id,
            "entity_type": "ip",
            "value": origin_ip,
            "label": origin_ip,
            "created_at": now,
        })
        edges.append({
            "_id": f"{email_node_id}_origin_{ip_node_id}",
            "source": email_node_id,
            "target": ip_node_id,
            "relation": "ORIGINATED_AT",
            "created_at": now,
        })

    # Attachments
    attachments = parsed_email.get("attachments") or []
    for att in attachments:
        sha_val = att.get("sha256")
        if sha_val:
            att_node_id = create_entity_id("attachment_sha256", sha_val)
            nodes.append({
                "_id": att_node_id,
                "entity_type": "attachment_sha256",
                "value": sha_val,
                "label": att.get("filename", sha_val[:12]),
                "created_at": now,
            })
            edges.append({
                "_id": f"{email_node_id}_att_{att_node_id}",
                "source": email_node_id,
                "target": att_node_id,
                "relation": "HAS_ATTACHMENT",
                "created_at": now,
            })

    # Persist in DB
    for node in nodes:
        try:
            await graph_nodes_collection.update_one(
                {"_id": node["_id"]},
                {"$setOnInsert": node},
                upsert=True,
            )
        except Exception:
            pass

    for edge in edges:
        try:
            await graph_edges_collection.update_one(
                {"_id": edge["_id"]},
                {"$setOnInsert": edge},
                upsert=True,
            )
        except Exception:
            pass

    return {
        "nodes_indexed": len(nodes),
        "edges_indexed": len(edges),
    }


async def correlate_email_campaigns(
    current_email_id: str,
    parsed_email: dict[str, Any],
    urls_data: dict[str, Any],
    relay_analysis: dict[str, Any],
) -> dict[str, Any]:
    reasons: list[str] = []
    matched_email_ids: set[str] = set()
    confidence_acc = 0.0

    current_email_node = f"email_{current_email_id}"

    # 1. Attachment SHA-256 correlation
    attachments = parsed_email.get("attachments") or []
    for att in attachments:
        sha_val = att.get("sha256")
        if sha_val:
            att_node_id = create_entity_id("attachment_sha256", sha_val)
            cursor = graph_edges_collection.find({"target": att_node_id, "relation": "HAS_ATTACHMENT"})
            async for edge in cursor:
                source = edge.get("source")
                if source and source != current_email_node and source.startswith("email_"):
                    peer_id = source[len("email_"):]
                    matched_email_ids.add(peer_id)
                    reasons.append(f"Shares identical attachment binary (SHA-256 {sha_val[:12]}...) with email {peer_id}")
                    confidence_acc += 0.45

    # 2. Suspicious URL correlation
    for u in (urls_data.get("all_urls") or [])[:15]:
        url_node_id = create_entity_id("url", u)
        cursor = graph_edges_collection.find({"target": url_node_id, "relation": "CONTAINS_URL"})
        async for edge in cursor:
            source = edge.get("source")
            if source and source != current_email_node and source.startswith("email_"):
                peer_id = source[len("email_"):]
                matched_email_ids.add(peer_id)
                reasons.append(f"Shares identical extracted URL ({u[:40]}...) with email {peer_id}")
                confidence_acc += 0.35

    # 3. Origin relay IP correlation
    primary_origin = relay_analysis.get("primary_origin")
    if primary_origin and primary_origin.get("ip"):
        origin_ip = primary_origin["ip"]
        ip_node_id = create_entity_id("ip", origin_ip)
        cursor = graph_edges_collection.find({"target": ip_node_id, "relation": "ORIGINATED_AT"})
        async for edge in cursor:
            source = edge.get("source")
            if source and source != current_email_node and source.startswith("email_"):
                peer_id = source[len("email_"):]
                matched_email_ids.add(peer_id)
                reasons.append(f"Shares originating transport IP ({origin_ip}) with email {peer_id}")
                confidence_acc += 0.25

    confidence = min(0.99, round(confidence_acc, 2)) if matched_email_ids else 0.0

    campaign_id = None
    if matched_email_ids:
        all_ids = sorted(list(matched_email_ids) + [current_email_id])
        campaign_seed = ":".join(all_ids)
        campaign_id = f"camp_{sha256(campaign_seed.encode('utf-8')).hexdigest()[:12]}"

    return {
        "campaign_id": campaign_id,
        "is_correlated": len(matched_email_ids) > 0,
        "confidence": confidence,
        "related_email_ids": list(matched_email_ids),
        "reasons": reasons,
    }
