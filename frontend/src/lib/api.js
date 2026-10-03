import axios from "axios";

const API = `${process.env.REACT_APP_BACKEND_URL}/api`;
const data = (r) => r.data;
const clean = (v) => v || undefined;

export const api = {
  summary: () => axios.get(`${API}/events/summary`).then(data),
  graph: ({ process_guid, start_time, end_time }) =>
    axios
      .get(`${API}/graph/${encodeURIComponent(process_guid)}`, {
        params: { start_time: clean(start_time), end_time: clean(end_time) },
      })
      .then(data),
  investigate: (body) => axios.post(`${API}/investigations`, body).then(data),
  investigations: () => axios.get(`${API}/investigations`).then(data),
  search: (q) => axios.get(`${API}/search`, { params: { q } }).then(data),
};

export const shortGuid = (g = "") => g.replace(/[{}]/g, "").split("-").slice(0, 2).join("-");
export const fmtTime = (ts) => (ts ? ts.replace("T", " ").replace("Z", "") : "—");
export const slug = (s = "") => s.toLowerCase().replace(/[^a-z0-9]+/g, "-");
