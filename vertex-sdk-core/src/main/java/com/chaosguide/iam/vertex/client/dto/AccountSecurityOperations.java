package com.chaosguide.iam.vertex.client.dto;

import java.lang.annotation.*;
import java.util.List;
import java.util.Map;

/** Current-user operation DTOs. Nullable wire fields may be absent or JSON null. */
public final class AccountSecurityOperations {
    private AccountSecurityOperations() {}
    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.RECORD_COMPONENT)
    public @interface NullableWire {}
    public enum MfaOperationType { TOTP_ENROLL, TOTP_DISABLE, RECOVERY_CODES_GENERATE }
    public enum MfaOperationState {
        AWAITING_REAUTH,
        READY,
        AWAITING_CONFIRMATION,
        COMMITTED,
        CANCELLED,
        EXPIRED
    }
    public enum ProofRequirement { SESSION, REAUTHENTICATION, STEP_UP }
    public enum ProofMethod { PASSWORD, EMAIL_OTP, PROVIDER, STEP_UP_PROOF }
    public enum SessionImpact { UNCHANGED, CURRENT_SESSION_RETAINED, REAUTHENTICATE }
    public enum SensitiveDelivery { AVAILABLE, ALREADY_DELIVERED, NOT_APPLICABLE }
    public enum IdentityOperationType {
        ADD,
        VERIFY,
        SET_PRIMARY,
        REMOVE,
        REPLACE,
        LINK,
        UNLINK,
        TRANSFER,
        ACCOUNT_DELETE
    }
    public enum IdentityOperationState {
        AWAITING_REAUTH,
        AWAITING_PROOF,
        READY,
        COMMITTED,
        CANCELLED,
        EXPIRED,
        REJECTED
    }
    public enum IdentifierKind { USERNAME, EMAIL, PHONE }
    public enum IdentifierAction { VERIFY, SET_PRIMARY, REMOVE, REPLACE, TRANSFER }
    public enum IdentifierDenial {
        ACCOUNT_INACTIVE,
        MANAGED_IDENTIFIER,
        METHOD_UNAVAILABLE,
        REAUTH_METHOD_UNAVAILABLE,
        TARGET_PROOF_UNAVAILABLE,
        IDENTIFIER_ALREADY_EXISTS,
        NOT_APPLICABLE,
        ALREADY_VERIFIED,
        ALREADY_PRIMARY,
        IDENTIFIER_UNVERIFIED,
        IDENTIFIER_RANGE_REJECTED,
        LAST_LOGIN_METHOD,
        PRIMARY_REPLACEMENT_UNAVAILABLE
    }
    public enum IdentifierRequirement {
        CURRENT_ACCOUNT_PROOF,
        NEW_IDENTIFIER,
        TARGET_EMAIL_OTP,
        TARGET_PHONE_OTP,
        REPLACEMENT_PRIMARY,
        REMOVE_OLD,
        COUNTERPART_CONFIRMATION,
        REMAINING_LOGIN_PATH
    }
    public enum TargetProofMethod { EMAIL_OTP, PHONE_OTP }
    public enum AuthorizationPurpose { CURRENT_ACCOUNT, TARGET_OWNERSHIP, TRANSFER_COUNTERPART }
    public enum TransferDecision { ACCEPT, REJECT }
    public sealed interface IdentityPayload permits AddIdentity, VerifyIdentity, SetPrimaryIdentity,
        RemoveIdentity, ReplaceIdentity, LinkIdentity, UnlinkIdentity, TransferIdentity {}
    public sealed interface Reauthentication permits PasswordReauthentication,
        EmailOtpReauthentication {}
    public record OperationProofOption(ProofMethod method, @NullableWire String identifierId,
        @NullableWire String maskedIdentifier, @NullableWire String methodId,
        @NullableWire String displayName, @NullableWire List<String> availableMethods) {
        public OperationProofOption {
            availableMethods = availableMethods == null ? null : List.copyOf(availableMethods);
        }
    }
    public record OperationCompletion(
        String completedAt, Long finalLoginMethodVersion, SessionImpact sessionImpact) {}
    public record MfaOperationResult(String completedAt, Long finalLoginMethodVersion,
        SessionImpact sessionImpact, @NullableWire String recoveryBatchId,
        @NullableWire Long recoveryCount) {}
    public record MfaAction(Boolean allowed, @NullableWire String reasonCode,
        ProofRequirement proofRequirement, List<OperationProofOption> proofOptions) {
        public MfaAction {
            proofOptions = proofOptions == null ? null : List.copyOf(proofOptions);
        }
    }
    public record MfaCapabilities(Long loginMethodVersion, MfaAction totpEnroll,
        MfaAction totpDisable, MfaAction recoveryCodesGenerate) {}
    public record MfaOperation(String id, MfaOperationType type, MfaOperationState state,
        String createdAt, String expiresAt, Long expectedLoginMethodVersion,
        ProofRequirement proofRequirement, List<OperationProofOption> proofOptions,
        Boolean proofSatisfied, @NullableWire String nextChallengeAt,
        @NullableWire String reasonCode, @NullableWire MfaOperationResult result) {
        public MfaOperation {
            proofOptions = proofOptions == null ? null : List.copyOf(proofOptions);
        }
    }
    public record TotpMaterial(String secret, String qrCodeUri, String issuer) {
        @Override
        public String toString() {
            return "TotpMaterial[redacted]";
        }
    }
    public record TotpBeginResult(
        MfaOperation operation, SensitiveDelivery delivery, @NullableWire TotpMaterial material) {
        @Override
        public String toString() {
            return "TotpBeginResult[redacted]";
        }
    }
    public record RecoveryCodesRemaining(Long remaining) {}
    public record RecoveryCodes(List<String> codes, Long count) {
        public RecoveryCodes {
            codes = codes == null ? null : List.copyOf(codes);
        }
        @Override
        public String toString() {
            return "RecoveryCodes[redacted]";
        }
    }
    public record MfaCompletionResult(MfaOperation operation, SensitiveDelivery delivery,
        @NullableWire RecoveryCodes recoveryCodes) {
        @Override
        public String toString() {
            return "MfaCompletionResult[redacted]";
        }
    }
    public record
        MfaChallengeResult(MfaOperation operation, String challengeId, String nextChallengeAt) {}
    public record IdentityRequiredProof(
        String purpose, List<String> methods, String strength, Boolean satisfied) {
        public IdentityRequiredProof {
            methods = methods == null ? null : List.copyOf(methods);
        }
    }
    public record IdentityOperation(String id, IdentityOperationType type,
        IdentityOperationState state, String expiresAt, List<IdentityRequiredProof> requiredProofs,
        @NullableWire Map<String, String> result, @NullableWire String maskedIdentifier,
        @NullableWire String nextChallengeAt, @NullableWire OperationCompletion completion,
        List<OperationProofOption> proofOptions, @NullableWire ProviderTarget providerTarget) {
        public IdentityOperation {
            requiredProofs = requiredProofs == null ? null : List.copyOf(requiredProofs);
            result = result == null ? null : Map.copyOf(result);
            proofOptions = proofOptions == null ? null : List.copyOf(proofOptions);
        }
    }
    public record ProviderTarget(String providerId, @NullableWire String maskedDisplayName,
        @NullableWire String maskedEmail, String reference) {}
    public record IdentifierCapability(Boolean allowed, List<IdentifierDenial> unavailableReasons,
        List<IdentifierRequirement> requirements, List<String> replacementPrimaryIds) {
        public IdentifierCapability {
            unavailableReasons =
                unavailableReasons == null ? null : List.copyOf(unavailableReasons);
            requirements = requirements == null ? null : List.copyOf(requirements);
            replacementPrimaryIds =
                replacementPrimaryIds == null ? null : List.copyOf(replacementPrimaryIds);
        }
    }
    public record IdentifierManagement(
        Map<IdentifierKind, IdentifierCapability> add, List<OperationProofOption> proofOptions) {
        public IdentifierManagement {
            add = add == null ? null : Map.copyOf(add);
            proofOptions = proofOptions == null ? null : List.copyOf(proofOptions);
        }
    }
    public record IdentityChallengeResult(
        IdentityOperation operation, String challengeId, String nextChallengeAt) {}
    public record
        ProviderAuthorization(String authorizationId, String authorizationUrl, String expiresAt) {}
    public record OperationStepUpChallenge(String challengeId, List<String> availableMethods) {
        public OperationStepUpChallenge {
            availableMethods = availableMethods == null ? null : List.copyOf(availableMethods);
        }
    }
    public record OperationWebAuthnStart(String requestId, String publicKey) {}
    public record AccountIdentifier(String id, IdentifierKind kind, String displayValue,
        String status, String verificationState, @NullableWire String verifiedAt,
        @NullableWire String verificationSource, Boolean isPrimary, @NullableWire String managedBy,
        @NullableWire Map<IdentifierAction, IdentifierCapability> capabilities) {
        public AccountIdentifier {
            capabilities = capabilities == null ? null : Map.copyOf(capabilities);
        }
    }
    public record AccountIdentifiers(Long loginMethodVersion, List<AccountIdentifier> items,
        @NullableWire IdentifierManagement management) {
        public AccountIdentifiers {
            items = items == null ? null : List.copyOf(items);
        }
    }
    public record AccountLoginMethod(String methodId, String kind, List<String> roles,
        String status, @NullableWire String identifierId, @NullableWire String credentialId,
        @NullableWire String identityId, @NullableWire String providerId,
        Map<String, Boolean> capabilities, List<String> unavailableReasons) {
        public AccountLoginMethod {
            roles = roles == null ? null : List.copyOf(roles);
            capabilities = capabilities == null ? null : Map.copyOf(capabilities);
            unavailableReasons =
                unavailableReasons == null ? null : List.copyOf(unavailableReasons);
        }
    }
    public record AccountLoginMethods(Long loginMethodVersion, List<AccountLoginMethod> methods) {
        public AccountLoginMethods {
            methods = methods == null ? null : List.copyOf(methods);
        }
    }
    public record LinkableIdentityProvider(String id, String providerType, String protocol,
        String displayName, Boolean enabled, Boolean linked, @NullableWire String linkedAt,
        Boolean supportsAccountLinking, Boolean canLink, Boolean canReauthenticate,
        List<String> unavailableReasons) {
        public LinkableIdentityProvider {
            unavailableReasons =
                unavailableReasons == null ? null : List.copyOf(unavailableReasons);
        }
    }
    public record MfaOperationCreate(MfaOperationType type, Long expectedLoginMethodVersion) {}
    public record LoginIdentifier(IdentifierKind kind, String value, @NullableWire String region) {}
    public record AddIdentity(LoginIdentifier identifier) implements IdentityPayload {}
    public record VerifyIdentity(String identifierId) implements IdentityPayload {}
    public record SetPrimaryIdentity(String identifierId) implements IdentityPayload {}
    public record RemoveIdentity(String identifierId, @NullableWire String replacementPrimaryId)
        implements IdentityPayload {}
    public record ReplaceIdentity(String identifierId, LoginIdentifier replacement,
        Boolean removeOld, @NullableWire String replacementPrimaryId) implements IdentityPayload {}
    public record LinkIdentity(String providerId) implements IdentityPayload {}
    public record UnlinkIdentity(String methodId) implements IdentityPayload {}
    public record TransferIdentity(String identifierId, String targetUserId,
        @NullableWire String sourceReplacementPrimaryId) implements IdentityPayload {}
    public record PasswordReauthentication(String password) implements Reauthentication {
        @Override
        public String toString() {
            return "PasswordReauthentication[redacted]";
        }
    }
    public record EmailOtpReauthentication(String challengeId, String code)
        implements Reauthentication {
        @Override
        public String toString() {
            return "EmailOtpReauthentication[redacted]";
        }
    }
    public record OperationStepUpVerify(String challengeId, String code) {
        @Override
        public String toString() {
            return "OperationStepUpVerify[redacted]";
        }
    }
    public record OperationWebAuthnVerify(String challengeId, String requestId, String credential) {
        @Override
        public String toString() {
            return "OperationWebAuthnVerify[redacted]";
        }
    }
    public record ProviderExchange(String authorizationId, String codeVerifier) {
        @Override
        public String toString() {
            return "ProviderExchange[redacted]";
        }
    }
    public record MfaProviderAuthorize(
        String methodId, String redirectUri, String codeChallenge, String codeChallengeMethod) {}
    public record IdentityProviderAuthorize(AuthorizationPurpose purpose, String redirectUri,
        String codeChallenge, String codeChallengeMethod, @NullableWire String methodId) {}
    public record IdentityTargetProof(TargetProofMethod method, String code) {
        @Override
        public String toString() {
            return "IdentityTargetProof[redacted]";
        }
    }
    public record IdentityOperationComplete(List<IdentityTargetProof> proofs) {
        public IdentityOperationComplete {
            proofs = proofs == null ? null : List.copyOf(proofs);
        }
        @Override
        public String toString() {
            return "IdentityOperationComplete[redacted]";
        }
    }
    public record
        IdentityOperationCreate(Long expectedLoginMethodVersion, IdentityPayload payload) {}
}
