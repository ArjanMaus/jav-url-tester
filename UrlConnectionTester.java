import javax.net.ssl.*;
import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.net.*;
import java.security.cert.Certificate;
import java.text.SimpleDateFormat;

public class UrlConnectionTester extends JFrame {
    private JTextField urlField, portField, timeoutField;
    private JComboBox<String> protocolBox;
    private JTextArea resultArea;

    public UrlConnectionTester() {
        setTitle("URL Connection Tester");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setLayout(new BorderLayout());

        JPanel inputPanel = new JPanel();
        inputPanel.add(new JLabel("Protocol:"));
        protocolBox = new JComboBox<>(new String[]{"http", "https"});
        inputPanel.add(protocolBox);
        inputPanel.add(new JLabel("URL/Host:"));
        urlField = new JTextField(18);
        inputPanel.add(urlField);
        inputPanel.add(new JLabel("Port:"));
        portField = new JTextField(5);
        inputPanel.add(portField);
        inputPanel.add(new JLabel("Timeout(ms):"));
        timeoutField = new JTextField("5000", 6);
        inputPanel.add(timeoutField);

        JButton testButton = new JButton("Test Connection");
        testButton.addActionListener(this::testConnection);
        inputPanel.add(testButton);

        add(inputPanel, BorderLayout.NORTH);

        resultArea = new JTextArea(18, 60);
        resultArea.setEditable(false);
        add(new JScrollPane(resultArea), BorderLayout.CENTER);

        pack();
        setLocationRelativeTo(null);
        setVisible(true);
    }

    private void testConnection(ActionEvent e) {
        resultArea.setText("");
        String userInput = urlField.getText().trim();
        String portStr = portField.getText().trim();
        String timeoutStr = timeoutField.getText().trim();
        String protocol = (String) protocolBox.getSelectedItem();

        int port, timeout;
        String host;
        String urlStr;

        try {
            timeout = Integer.parseInt(timeoutStr);
            if (timeout < 0) throw new NumberFormatException();
        } catch (Exception ex) {
            resultArea.append("Invalid timeout.\n");
            return;
        }

        // Parse host/URL and port
        try {
            if (userInput.matches("^[a-zA-Z]+://.*")) {
                URL parsed = new URL(userInput);
                protocol = parsed.getProtocol();
                host = parsed.getHost();
                port = portStr.isEmpty() ? (parsed.getPort() != -1 ? parsed.getPort() : getDefaultPort(protocol)) : Integer.parseInt(portStr);
                urlStr = protocol + "://" + host + ":" + port + (parsed.getPath().isEmpty() ? "/" : parsed.getPath());
            } else {
                // user may enter only host, optionally with ":port"
                if (userInput.contains(":")) {
                    String[] parts = userInput.split(":", 2);
                    host = parts[0];
                    port = Integer.parseInt(parts[1]);
                } else {
                    host = userInput;
                    port = portStr.isEmpty() ? getDefaultPort(protocol) : Integer.parseInt(portStr);
                }
                urlStr = protocol + "://" + host + ":" + port + "/";
            }
        } catch (Exception ex) {
            resultArea.append("Invalid input: " + ex.getMessage() + "\n");
            return;
        }

        resultArea.append("Requesting " + urlStr + " (timeout: " + timeout + "ms)...\n\n");

        if (protocol.equalsIgnoreCase("https")) {
            doHttpsRequest(urlStr, timeout);
        } else {
            doHttpRequest(urlStr, timeout);
        }
    }

    private void doHttpRequest(String urlStr, int timeout) {
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
            conn.setConnectTimeout(timeout);
            conn.setReadTimeout(timeout);
            conn.setRequestMethod("GET");

            // ---- Print response ----
            int code = conn.getResponseCode();
            resultArea.append("HTTP Status: " + code + " " + conn.getResponseMessage() + "\n");
            resultArea.append("---\nHeaders:\n");
            conn.getHeaderFields().forEach((k, v) -> resultArea.append((k == null ? "" : k + ": ") + v + "\n"));

            resultArea.append("---\nBody (first 4096 bytes):\n");
            try (InputStream in = (code >= 400 ? conn.getErrorStream() : conn.getInputStream())) {
                printStreamToArea(in);
            }
            conn.disconnect();
        } catch (IOException ex) {
            resultArea.append("HTTP request failed: " + ex.getMessage() + "\n");
        }
    }

    private void doHttpsRequest(String urlStr, int timeout) {
        try {
            HttpsURLConnection conn = (HttpsURLConnection) new URL(urlStr).openConnection();
            conn.setSSLSocketFactory((SSLSocketFactory) SSLSocketFactory.getDefault());
            conn.setConnectTimeout(timeout);
            conn.setReadTimeout(timeout);
            conn.setRequestMethod("GET");

            // ---- SSL Certificate Info ----
            conn.connect();
            resultArea.append("-- Certificate Info --\n");
            try {
                Certificate[] certs = conn.getServerCertificates();
                for (int i = 0; i < certs.length; i++) {
                    resultArea.append("Cert #" + i + ": " + certs[i].getType() + "\n" + certs[i].toString() + "\n");
                    if (certs[i] instanceof X509Certificate) {
                        X509Certificate x509 = (X509Certificate) certs[i];
                        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
                        resultArea.append("  Subject: " + x509.getSubjectDN() + "\n");
                        resultArea.append("  Issuer : " + x509.getIssuerDN() + "\n");
                        resultArea.append("  Valid  : " + sdf.format(x509.getNotBefore()) + " - " + sdf.format(x509.getNotAfter()) + "\n\n");
                    }
                }
            } catch (Exception ex) {
                resultArea.append("Could not fetch certificates: " + ex + "\n");
            }
            resultArea.append("\n");

            // ---- Print response ----
            int code = conn.getResponseCode();
            resultArea.append("HTTPS Status: " + code + " " + conn.getResponseMessage() + "\n");
            resultArea.append("---\nHeaders:\n");
            conn.getHeaderFields().forEach((k, v) -> resultArea.append((k == null ? "" : k + ": ") + v + "\n"));

            resultArea.append("---\nBody (first 4096 bytes):\n");
            try (InputStream in = (code >= 400 ? conn.getErrorStream() : conn.getInputStream())) {
                printStreamToArea(in);
            }
            conn.disconnect();
        } catch (SSLHandshakeException sslEx) {
            resultArea.append("Certificate handshake failed: " + sslEx + "\n");
        } catch (Exception ex) {
            resultArea.append("HTTPS request failed: " + ex + "\n");
        }
    }

    private int getDefaultPort(String protocol) {
        if ("https".equalsIgnoreCase(protocol)) return 443;
        if ("http".equalsIgnoreCase(protocol)) return 80;
        return -1;
    }

    private void printStreamToArea(InputStream in) throws IOException {
        if (in == null) {
            resultArea.append("No response body\n");
            return;
        }
        byte[] buf = new byte[4096];
        int read = in.read(buf);
        if (read > 0) {
            String text = new String(buf, 0, read);
            resultArea.append(text);
            if (read == buf.length) resultArea.append("\n--- body truncated ---\n");
        } else {
            resultArea.append("No data in body\n");
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(UrlConnectionTester::new);
    }
}