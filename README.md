# System Integrity Verifier(SIV)

A very simple system integrity verifier (SIV) for a Linux system. The goal of the SIV is to detect file system modifications occurring within a directory tree. The SIV outputs statistics and warnings about changes to a report file specified by the user.

The SIV can be run either in initialization mode or in verification mode.

# Environment

MacOS / Ubuntu 18.04

Python 3.6

# Usage

In the initialization mode, the hash function only supports 'md5' and 'sha1'.

``` shell
# Example 1: Initialization mode
python3 siv.py -i -D important_directory -V verificationDB.csv -R report.txt -H <digest>
```

``` shell
# Example 2: Verification mode
python3 siv.py -v -D important_directory -V verificationDB.csv -R report.txt
```

# LICENSE

               GLWT(Good Luck With That) Public License
                 Copyright (c) Everyone, except Author

Everyone is permitted to copy, distribute, modify, merge, sell, publish,
sublicense or whatever they want with this software but at their OWN RISK.

                            Preamble

The author has absolutely no clue what the code in this project does.
It might just work or not, there is no third option.


                GOOD LUCK WITH THAT PUBLIC LICENSE
   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION, AND MODIFICATION

  0. You just DO WHATEVER YOU WANT TO as long as you NEVER LEAVE A
TRACE TO TRACK THE AUTHOR of the original product to blame for or hold
responsible.

IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.

Good luck and Godspeed.
