import { useSelection } from "../lib/selection";
import { CountryDetail } from "./CountryDetail";
import { CveDetailView } from "./CveDetail";
import { Drawer } from "./Drawer";
import { countryName } from "./geoSummary";
import { StoryDetail } from "./StoryDetail";

/** Mounted once in the shell: shows the drawer for `?cve=` or `?story=`, nothing otherwise. */
export function DrawerHost() {
  const { selection, clear } = useSelection();
  if (!selection) return null;
  if (selection.kind === "cve") {
    return (
      <Drawer heading={<span className="mono">{selection.id}</span>} onClose={clear} focusKey={`cve:${selection.id}`}>
        <CveDetailView id={selection.id} />
      </Drawer>
    );
  }
  if (selection.kind === "country") {
    return (
      <Drawer heading={countryName(selection.cc)} onClose={clear} focusKey={`country:${selection.cc}`}>
        <CountryDetail cc={selection.cc} />
      </Drawer>
    );
  }
  return (
    <Drawer heading="Story" onClose={clear} focusKey={`story:${selection.url ?? ""}`}>
      <StoryDetail url={selection.url} />
    </Drawer>
  );
}
