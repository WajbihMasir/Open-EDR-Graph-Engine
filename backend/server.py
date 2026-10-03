from fastapi import FastAPI, APIRouter, HTTPException, Query
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import re
import logging
import uuid
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime, timezone

from graph_engine import build_graph, basename
from seed_data import shuffled_events, GOLDEN_TARGET, SUGGESTED_TARGETS

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

client = AsyncIOMotorClient(os.environ['MONGO_URL'])
db = client[os.environ['DB_NAME']]

app = FastAPI(title="Open-EDR Graph Engine")
api_router = APIRouter(prefix="/api")
logger = logging.getLogger(__name__)


class InvestigationRequest(BaseModel):
    process_guid: str
    start_time: Optional[str] = None
    end_time: Optional[str] = None


class Investigation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    process_guid: str
    target_image: str
    computer: Optional[str] = None
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    node_count: int
    edge_count: int
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class RawEvent(BaseModel):
    event_id: int
    timestamp: str
    computer: Optional[str] = None
    event_data: dict


async def load_events(start_time: Optional[str], end_time: Optional[str]):
    q = {}
    if start_time or end_time:
        q["timestamp"] = {}
        if start_time:
            q["timestamp"]["$gte"] = start_time
        if end_time:
            q["timestamp"]["$lte"] = end_time
    return await db.sysmon_events.find(q, {"_id": 0}).to_list(100000)


async def run_graph(guid, start_time, end_time):
    events = await load_events(start_time, end_time)
    graph = build_graph(events, guid)
    if graph is None:
        raise HTTPException(404, f"ProcessGuid {guid} not found in time window")
    graph["metadata"].update({"start_time": start_time, "end_time": end_time})
    return graph


@api_router.get("/")
async def root():
    return {"service": "open-edr-graph-engine", "status": "ok"}


@api_router.get("/graph/{process_guid}")
async def get_graph(process_guid: str, start_time: Optional[str] = None, end_time: Optional[str] = None):
    return await run_graph(process_guid, start_time, end_time)


@api_router.post("/investigations")
async def create_investigation(req: InvestigationRequest):
    graph = await run_graph(req.process_guid, req.start_time, req.end_time)
    meta = graph["metadata"]
    inv = Investigation(process_guid=req.process_guid, target_image=meta["target_image"], computer=meta["computer"],
                        start_time=req.start_time, end_time=req.end_time,
                        node_count=meta["node_count"], edge_count=meta["edge_count"])
    await db.investigations.insert_one(inv.model_dump())
    return {"investigation": inv.model_dump(), "graph": graph}


@api_router.get("/investigations", response_model=List[Investigation])
async def list_investigations():
    return await db.investigations.find({}, {"_id": 0}).sort("created_at", -1).to_list(20)


@api_router.get("/search")
async def search(q: str = Query(..., min_length=1)):
    rx = {"$regex": re.escape(q), "$options": "i"}
    ors = [{"event_data.ProcessGuid": rx}, {"event_data.Image": rx}, {"event_data.CommandLine": rx}]
    if q.isdigit():
        ors.append({"event_data.ProcessId": int(q)})
    docs = await db.sysmon_events.find({"event_id": 1, "$or": ors}, {"_id": 0}).sort("timestamp", 1).to_list(25)
    return [{"process_guid": d["event_data"]["ProcessGuid"], "image_name": basename(d["event_data"]["Image"]),
             "pid": d["event_data"]["ProcessId"], "user": d["event_data"].get("User"),
             "computer": d.get("computer"), "timestamp": d["timestamp"]} for d in docs]


@api_router.get("/events/summary")
async def events_summary():
    by_id = {str(r["_id"]): r["count"] async for r in db.sysmon_events.aggregate(
        [{"$group": {"_id": "$event_id", "count": {"$sum": 1}}}])}
    first = await db.sysmon_events.find_one({}, {"_id": 0, "timestamp": 1}, sort=[("timestamp", 1)])
    last = await db.sysmon_events.find_one({}, {"_id": 0, "timestamp": 1}, sort=[("timestamp", -1)])
    hosts = await db.sysmon_events.distinct("computer")
    return {"total": sum(by_id.values()), "by_event_id": by_id, "hosts": hosts,
            "time_range": {"start": first and first["timestamp"], "end": last and last["timestamp"]},
            "default_target": GOLDEN_TARGET, "suggested_targets": SUGGESTED_TARGETS}


@api_router.post("/events/ingest")
async def ingest(events: List[RawEvent]):
    if events:
        await db.sysmon_events.insert_many([e.model_dump() for e in events])
    return {"ingested": len(events)}


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')


@app.on_event("startup")
async def seed():
    if await db.sysmon_events.count_documents({}) == 0:
        await db.sysmon_events.insert_many(shuffled_events())
        logger.info("Seeded golden test case Sysmon events")
    await db.sysmon_events.create_index("timestamp")
    await db.sysmon_events.create_index("event_data.ProcessGuid")


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
