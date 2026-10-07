# Textual terminal interface

Install the optional extra with `pip install "certlord[textual]"`.

Run `certlord tui --ui textual`. Search the managed certificate inventory,
press Enter to read a certificate, and r to refresh. This browser is read-only;
issuing, importing, replacing and removing certificates remain CLI/API operations.
Failed reads leave the previous inventory visibly marked as stale.

Use / to search, Escape to cancel dialogs and q to quit. Requests run off the
UI thread; wait for pending requests before closing. The curses interface remains
available with `--ui curses`. Synthetic demonstrations are not production evidence.

## Synthetic interface examples

![Synthetic Textual textual-inventory](images/textual-inventory.png)

![Synthetic Textual textual-details](images/textual-details.png)
