package burp;

import java.io.PrintWriter;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.regex.*;
import com.google.gson.Gson;

public class BurpExtender implements IBurpExtender, IHttpListener, 
        IProxyListener, IScannerListener, IExtensionStateListener
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;

    //Magick numbers
    private static final byte[] INFO_DISCLOSURE_IMAGEMAGICK = "svg:base-uri".getBytes();
    private static final byte[] INFO_DISCLOSURE_IMAGEMAGICK_2 = "Thumb::URI".getBytes();


    //
    // implement IBurpExtender
    //

    private List<int[]> getMatches(byte[] response, byte[] match)
    {
        List<int[]> matches = new ArrayList<int[]>();

        int start = 0;
        while (start < response.length)
        {
            start = helpers.indexOf(response, match, true, start, response.length);
            if (start == -1)
                break;
            matches.add(new int[] { start, start + match.length });
            start += match.length;
        }

        return matches;
    }

    private List<String> getRegExMatches(byte[] response, String match){
        Pattern search = Pattern.compile(match);
        String str2response = helpers.bytesToString(response);
        Matcher matcher  = search.matcher(str2response);
        List<String> matches = new ArrayList<String>();
        while (matcher.find()){
            matches.add(matcher.group(1));
        }
        return matches;
    }

    private void searchImages(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {

        if (!messageIsRequest)
        {
            IRequestInfo analyzedReq = helpers.analyzeRequest(messageInfo);
            URL uUrl = analyzedReq.getUrl();
            String mimeInferred = helpers.analyzeResponse(messageInfo.getResponse()).getInferredMimeType();
            if ((mimeInferred.equalsIgnoreCase("JPEG"))
                    ||  (mimeInferred.equalsIgnoreCase("PNG"))
                    ||  (mimeInferred.equalsIgnoreCase("TIFF"))
                    ||  (mimeInferred.equalsIgnoreCase("GIF"))) {
                byte[] resp = messageInfo.getResponse();
                int responseOffset = helpers.analyzeResponse(resp).getBodyOffset();
                byte[] body = Arrays.copyOfRange(resp, responseOffset, resp.length);
                List<int[]> matches_imagemagic = getMatches(body, INFO_DISCLOSURE_IMAGEMAGICK);
                List<int[]> matches_imagemagic_2 = getMatches(body, INFO_DISCLOSURE_IMAGEMAGICK_2);
                List<int[]> match = new ArrayList<int[]>(matches_imagemagic);
                match.addAll(matches_imagemagic_2);
                if (match.size() > 0) {
                    stdout.println("### VULN : Vulnerable image found at " + uUrl.toString());
                    callbacks.addScanIssue(new CustomScanIssue(
                            messageInfo.getHttpService(),
                            helpers.analyzeRequest(messageInfo).getUrl(),
                            new IHttpRequestResponse[]{callbacks.applyMarkers(messageInfo, null, match)},
                            "Information disclosure at ImageMagick at converter tool",
                            "The response contains sensitive internal server information",
                            "Medium"));
                }
            }
        }
    }
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // helpers
        this.helpers = callbacks.getHelpers();
        
        // set our extension name
        callbacks.setExtensionName("ImageMagick Properties");
        
        // obtain our output stream
        stdout = new PrintWriter(callbacks.getStdout(), true);
        
        // register ourselves as an HTTP listener
        callbacks.registerHttpListener(this);
        
        // register ourselves as a Proxy listener
        callbacks.registerProxyListener(this);
        
        // register ourselves as a Scanner listener
        callbacks.registerScannerListener(this);
        
        // register ourselves as an extension state listener
        callbacks.registerExtensionStateListener(this);
    }

    //
    // implement IHttpListener
    //

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
        if(toolFlag!=callbacks.TOOL_REPEATER) searchImages(toolFlag, messageIsRequest, messageInfo);
    }

    //
    // implement IProxyListener
    //

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message)
    {
    }

    //
    // implement IScannerListener
    //

    @Override
    public void newScanIssue(IScanIssue issue)
    {

    }

    //
    // implement IExtensionStateListener
    //

    @Override
    public void extensionUnloaded()
    {
        stdout.println("Extension was unloaded");
    }
}