
!include "MUI2.nsh"

; Set branding text to match
BrandingText "DarkGuard"

; Attempt to set dark colors for the installer window (Experimental)
!define MUI_BGCOLOR "282828"
!define MUI_TEXTCOLOR "FFFFFF"
!define MUI_FINISHPAGE_NOAUTOCLOSE

; Hooks to colorize are limited in standard NSIS without plugins, 
; but we can ensure the sidebars are used correctly.
