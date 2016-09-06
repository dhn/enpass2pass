# enpass2pass
Import Enpass walletx.db to pass

## Usage

Enpass use AES-256 to encrypt the data and stored it into a sqlcipher database (walletx.db).

  ```
  $ enpass2pass.py ~/walletx.db "YOURENPASSPASSWORD"
  ```

## Notes
  * worked only with Python 2
  * imported only entries with ``templatetype``:
    * ``login.default``
    * ``computer.wifi``
