// A source-owned PE x64 DLL fixture for REA's real Ghidra provider lane.
// Cross-compiled using isolated MinGW-w64 on PVE161, never executed.
// Expected DLL SHA-256: f3b3bb1f7b97924ac6d366204152592ee2ce80a1a93061fccbf27e4524996f41.
extern "C" __declspec(dllexport)
int rea_lab_add(int a, int b) {
    return a + b + 7;
}
extern "C" __declspec(dllexport)
int rea_lab_mix(int a, int b) {
    return rea_lab_add(a, b) * 3 - 2;
}
