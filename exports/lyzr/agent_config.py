import os
from lyzr import Studio

studio = Studio(api_key=os.environ.get("LYZR_API_KEY", "dummy_key"))
agent = studio.create_agent(
    name="sentinel-threat-hunter",
    provider="openai",
    role="SOC Incident Commander",
    goal="Correlate telemetry alerts across endpoints and clouds, extract indicators of compromise (IOCs), and formulate automated containment runbooks.",
    instructions="Operate according to OpenGAP specifications."
)
