import type { EndpointSummary, Incident, IncidentDetail, Stats } from "@/lib/types";
import incidents from "@/fixtures/incidents.json";
import incidentDetail from "@/fixtures/incident-detail.json";
import endpoints from "@/fixtures/endpoints.json";
import stats from "@/fixtures/stats.json";

const useFixtures = process.env.NEXT_PUBLIC_USE_FIXTURES === "1";
const baseUrl = process.env.NEXT_PUBLIC_MONIKA_URL ?? "";

async function fixture<T>(value: T): Promise<T> {
  await new Promise((resolve) => setTimeout(resolve, 150));
  return value;
}

async function request<T>(path: string, fixtureValue: T): Promise<T> {
  if (useFixtures) return fixture(fixtureValue);
  const response = await fetch(`${baseUrl}${path}`);
  if (!response.ok) throw new Error(`Monika API request failed: ${response.status}`);
  return response.json() as Promise<T>;
}

export const api = {
  getIncidents: () => request<Incident[]>("/_monika/incidents", incidents as unknown as Incident[]),
  getIncident: (id: string) => request<IncidentDetail>(`/_monika/incidents/${id}`, incidentDetail as unknown as IncidentDetail),
  getEndpoints: () => request<EndpointSummary[]>("/_monika/endpoints", endpoints as unknown as EndpointSummary[]),
  getStats: () => request<Stats>("/_monika/stats", stats as unknown as Stats),
};
