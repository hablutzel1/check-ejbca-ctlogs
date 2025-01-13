package pe.blobfish;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import org.cesecore.certificates.certificatetransparency.CTLogInfo;
import org.cesecore.util.Base64GetHashMap;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.sql.*;
import java.time.ZonedDateTime;
import java.util.*;

public class CheckEjbcaCtLogs {
    // TODO ensure to handle unhandled exceptions as CRITICAL, e.g. database connectivity problems, Java object parsing or JSON download/parsing...
    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.out.println("Usage: check-ejbca-ctlogs <dbHost> <dbName> <user> <password>");
            // TODO check if 3 is right for Nagios's UNKNOWN and if it is appropriate in this case.
            System.exit(3);
        }

        String dbHost = args[0];
        String dbName = args[1];
        String user = args[2];
        String password = args[3];
        String url = "jdbc:mariadb://" + dbHost + ":3306/" + dbName;
        // FIXME the following has been observed producing the following in the MariaDB logs: [Warning] Aborted connection 112 to db: 'ejbca' user: 'nagios' host: 'monitoringhost.example.org' (Got an error reading communication packets)
        // TODO ensure this is closing the connections.
        try (Connection connection = DriverManager.getConnection(url, user, password)) {
            // TODO clarify the meaning of '0' here.
            String query = "SELECT data FROM GlobalConfigurationData WHERE configurationId = '0'";
            try (PreparedStatement statement = connection.prepareStatement(query);
                 ResultSet resultSet = statement.executeQuery()) {

                if (resultSet.next()) {
                    byte[] dataBytes = resultSet.getBytes("data");
                    try (ObjectInputStream objectInputStream = new ObjectInputStream(new ByteArrayInputStream(dataBytes))) {
                        Base64GetHashMap deserializedObject = (Base64GetHashMap) objectInputStream.readObject();
                        LinkedHashMap<Integer, CTLogInfo> ejbcaCtLogs = (LinkedHashMap) deserializedObject.get("ctlogs");

                        // TODO support to receive an indefinite size list of JSONs to intersect as arguments
                        Map<String, Log> googleCtLogList = loadJsonLogList("https://www.gstatic.com/ct/log_list/v3/log_list.json");
                        Map<String, Log> appleCtLogList = loadJsonLogList("https://valid.apple.com/ct/log_list/current_log_list.json");

                        List<String> intersectionLogIds = new ArrayList<>(googleCtLogList.keySet());
                        intersectionLogIds.retainAll(appleCtLogList.keySet());

                        List<String> eligibleCtLogs = new ArrayList<>();
                        for (String logId : intersectionLogIds) {
                            Log googleLog = googleCtLogList.get(logId);
                            Log appleLog = appleCtLogList.get(logId);
                            Map<String, Object> googleLogState = googleLog.getState();
                            Map<String, Object> appleLogState = appleLog.getState();
                            // TODO check: maybe the following comparison is not needed as long as the 'usable' state is present in both logs.
                            if (googleLogState.keySet().equals(appleLogState.keySet())) {
                                if (googleLogState.containsKey("usable") && appleLogState.containsKey("usable")) {

                                    // TODO check at least one of our roots is accepted by this log? This could be optionally configured later. For now, having the ability to exclude some Operators from the monitoring should be enough.

                                    // TODO check the end of the temporal interval for the Apple logs as well.
                                    // FIXME the following is assuming all the logs have a temporal interval, which is not correct.
                                    java.time.ZonedDateTime endExclusive = java.time.ZonedDateTime.parse(googleLog.getTemporalInterval().getEndExclusive());
                                    if (java.time.ZonedDateTime.now().isBefore(endExclusive)) {
                                        eligibleCtLogs.add(logId);
                                    }
                                }
                            }
                        }

                        boolean isWarning = false;
                        boolean isCritical = false;
                        for (String eligibleLogId : eligibleCtLogs) {
                            Log googleLog = googleCtLogList.get(eligibleLogId);
                            // TODO support Apple's list for the following check as well and maybe use an intersection of the intervals.
                            // Assuming all logs will have a temporal interval. FIXME this assumption isn't correct.
                            java.time.ZonedDateTime expectedStart = java.time.ZonedDateTime.parse(googleLog.getTemporalInterval().getStartInclusive());
                            java.time.ZonedDateTime expectedEnd = java.time.ZonedDateTime.parse(googleLog.getTemporalInterval().getEndExclusive());
                            boolean foundInEjbca = false;
                            for (CTLogInfo ejbcaCtLog : ejbcaCtLogs.values()) {
                                String ejbcaPublicKeySha256 = java.util.Base64.getEncoder().encodeToString(java.security.MessageDigest.getInstance("SHA-256").digest(ejbcaCtLog.getPublicKeyBytes()));
                                if (ejbcaPublicKeySha256.equals(eligibleLogId)) {
                                    foundInEjbca = true;
                                    if (!ejbcaCtLog.getUrl().startsWith(googleLog.getUrl())) {
                                        System.out.println("The URL of the log with ID " + eligibleLogId + " is different in EJBCA: " + ejbcaCtLog.getUrl() + " vs " + googleLog.getUrl());
                                        isCritical = true;
                                    }
                                    Integer ejbcaExpirationYear = ejbcaCtLog.getExpirationYearRequired();
                                    if (ejbcaExpirationYear != null) {
                                        java.time.ZonedDateTime actualStart = java.time.ZonedDateTime.of(ejbcaExpirationYear, 1, 1, 0, 0, 0, 0, java.time.ZoneId.of("Z"));
                                        ZonedDateTime actualEnd = actualStart.plusYears(1);
                                        if (!actualStart.equals(expectedStart) || !actualEnd.equals(expectedEnd)) {
                                            System.out.println("The temporal interval of the log with ID " + eligibleLogId + " is different in EJBCA. Actual: " + actualStart + " - " + actualEnd + ", Expected: " + expectedStart + " - " + expectedEnd);
                                            isCritical = true;
                                        }
                                    } else if (ejbcaCtLog.getIntervalStart() != null && ejbcaCtLog.getIntervalEnd() != null) {
                                        java.time.ZonedDateTime actualStart = java.time.ZonedDateTime.ofInstant(ejbcaCtLog.getIntervalStart().toInstant(), java.time.ZoneId.of("Z"));
                                        java.time.ZonedDateTime actualEnd = java.time.ZonedDateTime.ofInstant(ejbcaCtLog.getIntervalEnd().toInstant(), java.time.ZoneId.of("Z"));
                                        // TODO determine why is EJBCA extending the end of the interval until the end of the day, e.g. 2025-07-01T23:59:59Z. Possibly a bug in EJBCA.
                                        actualEnd = actualEnd.withHour(0).withMinute(0).withSecond(0).withNano(0);
                                        if (!actualStart.equals(expectedStart) || !actualEnd.equals(expectedEnd)) {
                                            System.out.println("The temporal interval of the log with ID " + eligibleLogId + " is different in EJBCA. Actual: " + actualStart + " - " + actualEnd + ", Expected: " + expectedStart + " - " + expectedEnd);
                                            isCritical = true;
                                        }
                                    } else {
                                        System.out.println("The temporal interval of the log with ID " + eligibleLogId + " is missing in EJBCA. Expected: " + expectedStart + " - " + expectedEnd);
                                        isCritical = true;
                                    }
                                }
                            }
                            if (!foundInEjbca) {
                                System.out.println("Missing in EJBCA: " + eligibleLogId + ", " + googleLog.getUrl() + ", " + googleLog.getKey() + ", " + expectedStart + " - " + expectedEnd);
                                isWarning = true;
                            }
                        }

                        if (isCritical) {
                            System.exit(2);
                        } else if (isWarning) {
                            System.exit(1);
                        } else {
                            System.out.println("All logs common to Google and Apple are correctly configured in EJBCA.");
                            System.exit(0);
                        }
                    }
                }
            }
        }
    }

    private static Map<String, Log> loadJsonLogList(String urlOrFile) throws Exception {
        String json = "";
        if (urlOrFile.startsWith("http://") || urlOrFile.startsWith("https://")) {
            OkHttpClient client = new OkHttpClient();
            Request request = new Request.Builder()
                    .url(urlOrFile)
                    .build();
            try (Response response = client.newCall(request).execute()) {
                if (!response.isSuccessful()) {
                    System.out.println("Failed to download file: " + response);
                    return null;
                }
                if (response.body() != null) {
                    byte[] fileBytes = response.body().bytes();
                    json = new String(fileBytes);
                } else {
                    System.out.println("No content received from the server.");
                }
            } catch (IOException e) {
                System.out.println("Error occurred while downloading the file: " + e.getMessage());
                throw new RuntimeException(e);
            }
        } else {
            try {
                json = new String(java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(urlOrFile)));
            } catch (IOException e) {
                System.out.println("Error occurred while reading the file: " + e.getMessage());
                throw new RuntimeException(e);
            }
        }
        ObjectMapper objectMapper = new ObjectMapper();
        LogList logList = objectMapper.readValue(json, new TypeReference<>() {
        });

        Map<String, Log> logWithOperatorList = new HashMap<>();
        for (Operator operator : logList.getOperators()) {
            // TODO allow to optionally exclude some operators, e.g. when they don't support our roots.
            for (Log log : operator.getLogs()) {
                logWithOperatorList.put(log.getLogId(), log);
            }
        }
        return logWithOperatorList;

    }
}

@JsonIgnoreProperties(ignoreUnknown = true)
class LogList {
    private String version;
    private String log_list_timestamp;
    private List<Operator> operators;

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getLogListTimestamp() {
        return log_list_timestamp;
    }

    public void setLogListTimestamp(String log_list_timestamp) {
        this.log_list_timestamp = log_list_timestamp;
    }

    public List<Operator> getOperators() {
        return operators;
    }

    public void setOperators(List<Operator> operators) {
        this.operators = operators;
    }
}

@JsonIgnoreProperties(ignoreUnknown = true)
class Operator {
    private String name;
    private List<String> email;
    private List<Log> logs;

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<String> getEmail() {
        return email;
    }

    public void setEmail(List<String> email) {
        this.email = email;
    }

    public List<Log> getLogs() {
        return logs;
    }

    public void setLogs(List<Log> logs) {
        this.logs = logs;
    }
}

@JsonIgnoreProperties(ignoreUnknown = true)
class Log {
    private String description;
    private String log_id;
    private String key;
    private String url;
    private int mmd;
    private Map<String, Object> state;
    private TemporalInterval temporal_interval;

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    @com.fasterxml.jackson.annotation.JsonProperty("log_id")
    public String getLogId() {
        return log_id;
    }

    public void setLogId(String log_id) {
        this.log_id = log_id;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public int getMmd() {
        return mmd;
    }

    public void setMmd(int mmd) {
        this.mmd = mmd;
    }

    public Map<String, Object> getState() {
        return state;
    }

    public void setState(Map<String, Object> state) {
        this.state = state;
    }

    @com.fasterxml.jackson.annotation.JsonProperty("temporal_interval")
    public TemporalInterval getTemporalInterval() {
        return temporal_interval;
    }

    public void setTemporalInterval(TemporalInterval temporal_interval) {
        this.temporal_interval = temporal_interval;
    }
}

@JsonIgnoreProperties(ignoreUnknown = true)
class TemporalInterval {
    private String start_inclusive;
    private String end_exclusive;

    @com.fasterxml.jackson.annotation.JsonProperty("start_inclusive")
    public String getStartInclusive() {
        return start_inclusive;
    }

    public void setStartInclusive(String start_inclusive) {
        this.start_inclusive = start_inclusive;
    }

    @com.fasterxml.jackson.annotation.JsonProperty("end_exclusive")
    public String getEndExclusive() {
        return end_exclusive;
    }

    public void setEndExclusive(String end_exclusive) {
        this.end_exclusive = end_exclusive;
    }
}