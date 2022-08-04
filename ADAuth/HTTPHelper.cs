namespace ADAuth
{
    public class HTTPHelper
    {
        public static string MakePostBodyWithRedirect(string? displayText, Dictionary<string,string>? parameters, string redirectURL)
        {
            return $@"
                <html>
                    <body onload='document.forms[""form""].submit()'>
                        { displayText }
                        <form name='form' action='{ redirectURL }' method='POST'>
                        {(
                            parameters != null ? String.Join (Environment.NewLine, parameters.Select(parameter => $"<input type='hidden' name='{ parameter.Key }' value='{ parameter.Value }'>")) : ""
                        )}   
                        </form>
                    </body>
                </html>
            "; 
        }

    }
}
