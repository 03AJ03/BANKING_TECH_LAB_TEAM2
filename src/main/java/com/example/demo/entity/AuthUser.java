package com.example.demo.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "AUTH_USERS")
public class AuthUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "USR_ID")
    private Long usrId;

    @Column(name = "USR_USERNAME", nullable = false, unique = true)
    private String usrUsername;

    @Column(name = "USR_EMAIL", nullable = false)
    private String usrEmail;

    @Column(name = "USR_PASSWORD_HASH", nullable = false)
    private String usrPasswordHash;

    @Column(name = "USR_ROLE")
    private String usrRole;

    @Column(name = "USR_STS")
    private String usrSts;

    @Column(name = "USR_USR_ID")
    private String usrUsrId;

    @Column(name = "USR_WS_ID")
    private String usrWsId;

    @Column(name = "USR_LOCAL_TS")
    private LocalDateTime usrLocalTs;

    @Column(name = "USR_HOST_TS")
    private LocalDateTime usrHostTs;

    @Column(name = "USR_PRGM_ID")
    private String usrPrgmId;

    @Column(name = "USR_ACPT_TS")
    private LocalDateTime usrAcptTs;

    @Column(name = "USR_ACPT_TS_UTC_OSFT")
    private String usrAcptTsUtcOsft;

    @Column(name = "USR_UUID")
    private String usrUuid;

    @Column(name = "USR_CRUD_VAL")
    private String usrCrudVal;

    public AuthUser() {
    }

    public AuthUser(Long usrId, String usrUsername, String usrEmail, String usrPasswordHash, String usrRole,
                    String usrSts, String usrUsrId, String usrWsId, LocalDateTime usrLocalTs, LocalDateTime usrHostTs,
                    String usrPrgmId, LocalDateTime usrAcptTs, String usrAcptTsUtcOsft, String usrUuid, String usrCrudVal) {
        this.usrId = usrId;
        this.usrUsername = usrUsername;
        this.usrEmail = usrEmail;
        this.usrPasswordHash = usrPasswordHash;
        this.usrRole = usrRole;
        this.usrSts = usrSts;
        this.usrUsrId = usrUsrId;
        this.usrWsId = usrWsId;
        this.usrLocalTs = usrLocalTs;
        this.usrHostTs = usrHostTs;
        this.usrPrgmId = usrPrgmId;
        this.usrAcptTs = usrAcptTs;
        this.usrAcptTsUtcOsft = usrAcptTsUtcOsft;
        this.usrUuid = usrUuid;
        this.usrCrudVal = usrCrudVal;
    }

    public Long getUsrId() {
        return usrId;
    }

    public void setUsrId(Long usrId) {
        this.usrId = usrId;
    }

    public String getUsrUsername() {
        return usrUsername;
    }

    public void setUsrUsername(String usrUsername) {
        this.usrUsername = usrUsername;
    }

    public String getUsrEmail() {
        return usrEmail;
    }

    public void setUsrEmail(String usrEmail) {
        this.usrEmail = usrEmail;
    }

    public String getUsrPasswordHash() {
        return usrPasswordHash;
    }

    public void setUsrPasswordHash(String usrPasswordHash) {
        this.usrPasswordHash = usrPasswordHash;
    }

    public String getUsrRole() {
        return usrRole;
    }

    public void setUsrRole(String usrRole) {
        this.usrRole = usrRole;
    }

    public String getUsrSts() {
        return usrSts;
    }

    public void setUsrSts(String usrSts) {
        this.usrSts = usrSts;
    }

    public String getUsrUsrId() {
        return usrUsrId;
    }

    public void setUsrUsrId(String usrUsrId) {
        this.usrUsrId = usrUsrId;
    }

    public String getUsrWsId() {
        return usrWsId;
    }

    public void setUsrWsId(String usrWsId) {
        this.usrWsId = usrWsId;
    }

    public LocalDateTime getUsrLocalTs() {
        return usrLocalTs;
    }

    public void setUsrLocalTs(LocalDateTime usrLocalTs) {
        this.usrLocalTs = usrLocalTs;
    }

    public LocalDateTime getUsrHostTs() {
        return usrHostTs;
    }

    public void setUsrHostTs(LocalDateTime usrHostTs) {
        this.usrHostTs = usrHostTs;
    }

    public String getUsrPrgmId() {
        return usrPrgmId;
    }

    public void setUsrPrgmId(String usrPrgmId) {
        this.usrPrgmId = usrPrgmId;
    }

    public LocalDateTime getUsrAcptTs() {
        return usrAcptTs;
    }

    public void setUsrAcptTs(LocalDateTime usrAcptTs) {
        this.usrAcptTs = usrAcptTs;
    }

    public String getUsrAcptTsUtcOsft() {
        return usrAcptTsUtcOsft;
    }

    public void setUsrAcptTsUtcOsft(String usrAcptTsUtcOsft) {
        this.usrAcptTsUtcOsft = usrAcptTsUtcOsft;
    }

    public String getUsrUuid() {
        return usrUuid;
    }

    public void setUsrUuid(String usrUuid) {
        this.usrUuid = usrUuid;
    }

    public String getUsrCrudVal() {
        return usrCrudVal;
    }

    public void setUsrCrudVal(String usrCrudVal) {
        this.usrCrudVal = usrCrudVal;
    }
}
