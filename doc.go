/*
Package masterpassword implements the MasterPassword algorithm (http://masterpasswordapp.com/algorithm.html).

Usage:

Create a session from the user name and the password using NewSession.
Then, instantiate a site with NewSite or NewSiteWithCounter.

Finally, you can generate the password using the Password method on the Site.
Password requires you to specify the type of password using a PasswordType.

*PasswordType implements the Value interface from the flags package, making it easy to use it
as a command line parameter:

    import "flag"
    var pwdType = PasswordTypeBasic

    func main() {
        flag.Var(&pwdType, "type", "password type")
    }
*/
package masterpassword
