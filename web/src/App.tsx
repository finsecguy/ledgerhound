import { NavLink, Route, Routes } from "react-router-dom";

import AssessmentReview from "./pages/AssessmentReview";
import CampaignDetail from "./pages/CampaignDetail";
import CampaignList from "./pages/CampaignList";
import FeedBrowser from "./pages/FeedBrowser";
import Overview from "./pages/Overview";
import ReportViewer from "./pages/ReportViewer";
import Settings from "./pages/Settings";

function navClass({ isActive }: { isActive: boolean }): string {
  return isActive ? "active" : "";
}

export default function App(): React.JSX.Element {
  return (
    <div className="app-shell">
      <nav className="app-nav">
        <div className="app-nav__brand">
          Ledger<span>hound</span>
        </div>
        <NavLink to="/" end className={navClass}>
          Overview
        </NavLink>
        <NavLink to="/campaigns" className={navClass}>
          Campaigns
        </NavLink>
        <NavLink to="/feed" className={navClass}>
          IOC Feed
        </NavLink>
        <NavLink to="/settings" className={navClass}>
          Settings
        </NavLink>
      </nav>
      <main className="app-main">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/campaigns" element={<CampaignList />} />
          <Route path="/campaigns/:code" element={<CampaignDetail />} />
          <Route path="/campaigns/:code/assessment" element={<AssessmentReview />} />
          <Route path="/campaigns/:code/report" element={<ReportViewer />} />
          <Route path="/feed" element={<FeedBrowser />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
    </div>
  );
}
