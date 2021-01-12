package com.hedera.services.txns.schedule;

import com.google.protobuf.ByteString;
import com.hedera.services.context.TransactionContext;
import com.hedera.services.keys.KeysHelper;
import com.hedera.services.ledger.HederaLedger;
import com.hedera.services.legacy.core.jproto.JEd25519Key;
import com.hedera.services.legacy.core.jproto.JKey;
import com.hedera.services.legacy.core.jproto.JKeyList;
import com.hedera.services.legacy.core.jproto.JThresholdKey;
import com.hedera.services.legacy.crypto.SignatureStatus;
import com.hedera.services.legacy.crypto.SignatureStatusCode;
import com.hedera.services.sigs.order.HederaSigningOrder;
import com.hedera.services.sigs.order.SigningOrderResult;
import com.hedera.services.state.merkle.MerkleAccount;
import com.hedera.services.state.merkle.MerkleSchedule;
import com.hedera.services.state.submerkle.EntityId;
import com.hedera.services.state.submerkle.RichInstant;
import com.hedera.services.store.schedule.ScheduleStore;
import com.hedera.services.utils.PlatformTxnAccessor;
import com.hedera.test.factories.txns.SignedTxnFactory;
import com.hedera.test.utils.IdUtils;
import com.hedera.test.utils.TxnUtils;
import com.hederahashgraph.api.proto.java.CryptoTransferTransactionBody;
import com.hederahashgraph.api.proto.java.ResponseCodeEnum;
import com.hederahashgraph.api.proto.java.ScheduleID;
import com.hederahashgraph.api.proto.java.ScheduleSignTransactionBody;
import com.hederahashgraph.api.proto.java.SignatureMap;
import com.hederahashgraph.api.proto.java.SignaturePair;
import com.hederahashgraph.api.proto.java.TransactionBody;
import com.hederahashgraph.api.proto.java.TransactionID;
import com.hederahashgraph.api.proto.java.TransferList;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.KeyPairGenerator;
import org.apache.commons.codec.DecoderException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.platform.runner.JUnitPlatform;
import org.junit.runner.RunWith;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static com.hedera.services.legacy.core.jproto.JKey.equalUpToDecodability;
import static com.hedera.test.utils.IdUtils.asAccount;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.FAIL_INVALID;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.INVALID_KEY_ENCODING;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.INVALID_SCHEDULE_ID;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.OK;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.SCHEDULE_EXECUTION_ERROR;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.SCHEDULE_EXECUTION_INVALID_ACCOUNT_ID;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.SCHEDULE_EXECUTION_INVALID_PAYER_ACCOUNT_ID;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.SUCCESS;
import static junit.framework.TestCase.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@RunWith(JUnitPlatform.class)
public class ScheduleSignTransitionLogicTest {
    private HederaLedger ledger;
    private HederaSigningOrder signingOrder;
    private ScheduleStore store;
    private PlatformTxnAccessor accessor;
    private TransactionContext txnCtx;

    private TransactionBody scheduleSignTxn;
    private TransactionBody innerTransactionBody;

    private SignatureMap.Builder sigMap;
    private Set<JKey> jKeySet;

    private ScheduleSignTransitionLogic subject;
    private ScheduleID schedule = IdUtils.asSchedule("1.2.3");
    private EntityId payerAccount = new EntityId(4, 5, 6);
    private MerkleSchedule merkleSchedule;
    private MerkleAccount merkleAccount;
    private JKey payerPubKey;
    private List<JKey> wrongOtherPartiesKeysList;
    private final ResponseCodeEnum NOT_OK = null;
    private SignatureStatus failureAccountIdSignatureStatus;
    private SignatureStatus failureSignatureCountMismatch;

    @BeforeEach
    private void setup() throws DecoderException {
        ledger = mock(HederaLedger.class);
        signingOrder = mock(HederaSigningOrder.class);
        store = mock(ScheduleStore.class);
        accessor = mock(PlatformTxnAccessor.class);

        txnCtx = mock(TransactionContext.class);
        failureAccountIdSignatureStatus = new SignatureStatus(
                SignatureStatusCode.INVALID_ACCOUNT_ID, ResponseCodeEnum.INVALID_ACCOUNT_ID,
                false, TransactionID.newBuilder().build(),
                SignedTxnFactory.DEFAULT_PAYER, null, null, null);
        failureSignatureCountMismatch = new SignatureStatus(
                SignatureStatusCode.KEY_COUNT_MISMATCH, ResponseCodeEnum.INVALID_SIGNATURE_COUNT_MISMATCHING_KEY,
                true, TransactionID.newBuilder().build(),
                null, null, null, null);
        wrongOtherPartiesKeysList = new ArrayList<>();
        wrongOtherPartiesKeysList.add(new JThresholdKey(new JKeyList(List.of(new JEd25519Key("ASD".getBytes()))), 1));

        subject = new ScheduleSignTransitionLogic(ledger, signingOrder, store, txnCtx);
    }

    @Test
    public void hasCorrectApplicability() {
        givenValidTxnCtx();

        // expect:
        assertTrue(subject.applicability().test(scheduleSignTxn));
        assertFalse(subject.applicability().test(TransactionBody.getDefaultInstance()));
    }

    @Test
    public void validNotReadyForExecutionPayerKeyNotFound() throws DecoderException {
        // given:
        givenValidTxnCtx();
        // and:
        given(store.addSigners(eq(schedule), argThat(jKeySet -> true))).willReturn(OK);
        // and:
        var otherMerkleAccount = new MerkleAccount();
        otherMerkleAccount.setKey(randomPubKey());
        given(ledger.get(payerAccount.toGrpcAccountId())).willReturn(otherMerkleAccount);

        // when:
        subject.doStateTransition();

        // then:
        verify(store).addSigners(eq(schedule), argThat(this::assertJKeySet));
        // and:
        verify(store).get(eq(schedule));
        verify(ledger).exists(payerAccount.toGrpcAccountId());
        verify(ledger).get(payerAccount.toGrpcAccountId());
        verify(signingOrder, never()).keysForOtherParties(innerTransactionBody, ScheduleReadyForExecution.PRE_HANDLE_SUMMARY_FACTORY);
        // and:
        verify(txnCtx).setStatus(SUCCESS);
    }

    @Test
    public void validNotReadyForExecutionOtherPartyTresholdKeyNotFound() {
        // given:
        givenValidTxnCtx();
        // and:
        given(store.addSigners(eq(schedule), argThat(jKeySet -> true))).willReturn(OK);
        // and:
        given(signingOrder.keysForOtherParties(innerTransactionBody, ScheduleReadyForExecution.PRE_HANDLE_SUMMARY_FACTORY))
                .willReturn(new SigningOrderResult<>(wrongOtherPartiesKeysList));

        // when:
        subject.doStateTransition();

        // then:
        verify(store).addSigners(eq(schedule), argThat(this::assertJKeySet));
        // and:
        verify(store).get(eq(schedule));
        verify(ledger).exists(payerAccount.toGrpcAccountId());
        verify(ledger).get(payerAccount.toGrpcAccountId());
        verify(signingOrder).keysForOtherParties(innerTransactionBody, ScheduleReadyForExecution.PRE_HANDLE_SUMMARY_FACTORY);
        // and:
        verify(txnCtx).setStatus(SUCCESS);
    }

    @Test
    public void validNotReadyForExecutionOtherPartyJKeyListNotFound() {
        // given:
        givenValidTxnCtx();
        // and:
        given(store.addSigners(eq(schedule), argThat(jKeySet -> true))).willReturn(OK);
        // and:
        wrongOtherPartiesKeysList = new ArrayList<>();
        wrongOtherPartiesKeysList.add(new JKeyList(List.of(new JEd25519Key("AbCdEfGhIjKlMnOpQrStUvWxYz012345".getBytes()))));
        given(signingOrder.keysForOtherParties(innerTransactionBody, ScheduleReadyForExecution.PRE_HANDLE_SUMMARY_FACTORY))
                .willReturn(new SigningOrderResult<>(wrongOtherPartiesKeysList));

        // when:
        subject.doStateTransition();

        // then
        verify(store).addSigners(eq(schedule), argThat(this::assertJKeySet));
        // and:
        verify(store).get(eq(schedule));
        verify(ledger).exists(payerAccount.toGrpcAccountId());
        verify(ledger).get(payerAccount.toGrpcAccountId());
        verify(signingOrder).keysForOtherParties(innerTransactionBody, ScheduleReadyForExecution.PRE_HANDLE_SUMMARY_FACTORY);
        // and:
        verify(txnCtx).setStatus(SUCCESS);
    }

    @Test
    public void readyForExecutionThrowsNonExistentPayer() {
        // given:
        givenValidTxnCtx();
        // and:
        given(store.addSigners(eq(schedule), argThat(jKeySet -> true))).willReturn(OK);
        // and:
        given(ledger.exists(payerAccount.toGrpcAccountId())).willReturn(false);

        // when:
        subject.doStateTransition();

        // then:
        verify(store).addSigners(eq(schedule), argThat(this::assertJKeySet));
        // and:
        verify(store).get(eq(schedule));
        verify(ledger).exists(payerAccount.toGrpcAccountId());
        verify(ledger, never()).get(payerAccount.toGrpcAccountId());
        verify(signingOrder, never()).keysForOtherParties(innerTransactionBody, ScheduleReadyForExecution.PRE_HANDLE_SUMMARY_FACTORY);
        // and:
        verify(txnCtx).setStatus(SCHEDULE_EXECUTION_INVALID_PAYER_ACCOUNT_ID);
    }

    @Test
    public void readyForExecutionThrowsOtherPartiesInvalidAccountID() {
        // given:
        givenValidTxnCtx();
        // and:
        given(store.addSigners(eq(schedule), argThat(jKeySet -> true))).willReturn(OK);
        // and:
        given(signingOrder.keysForOtherParties(innerTransactionBody, ScheduleReadyForExecution.PRE_HANDLE_SUMMARY_FACTORY))
                .willReturn(new SigningOrderResult<>(failureAccountIdSignatureStatus));

        // when:
        subject.doStateTransition();

        // then:
        verify(store).addSigners(eq(schedule), argThat(this::assertJKeySet));
        // and:
        verify(store).get(eq(schedule));
        verify(ledger).exists(payerAccount.toGrpcAccountId());
        verify(ledger).get(payerAccount.toGrpcAccountId());
        verify(signingOrder).keysForOtherParties(innerTransactionBody, ScheduleReadyForExecution.PRE_HANDLE_SUMMARY_FACTORY);
        // and:
        verify(txnCtx).setStatus(SCHEDULE_EXECUTION_INVALID_ACCOUNT_ID);
    }

    @Test
    public void readyForExecutionThrowsOtherPartiesError() {
        // given:
        givenValidTxnCtx();
        // and:
        given(store.addSigners(eq(schedule), argThat(jKeySet -> true))).willReturn(OK);
        // and:
        given(signingOrder.keysForOtherParties(innerTransactionBody, ScheduleReadyForExecution.PRE_HANDLE_SUMMARY_FACTORY))
                .willReturn(new SigningOrderResult<>(failureSignatureCountMismatch));

        // when:
        subject.doStateTransition();

        // then:
        verify(store).addSigners(eq(schedule), argThat(this::assertJKeySet));
        // and:
        verify(store).get(eq(schedule));
        verify(ledger).exists(payerAccount.toGrpcAccountId());
        verify(ledger).get(payerAccount.toGrpcAccountId());
        verify(signingOrder).keysForOtherParties(innerTransactionBody, ScheduleReadyForExecution.PRE_HANDLE_SUMMARY_FACTORY);
        // and:
        verify(txnCtx).setStatus(SCHEDULE_EXECUTION_ERROR);
    }

    @Test
    public void followsHappyPath() {
        // given:
        givenValidTxnCtx();
        // and:
        given(store.addSigners(eq(schedule), argThat(jKeySet -> true))).willReturn(OK);

        // when:
        subject.doStateTransition();

        // then:
        verify(store).addSigners(eq(schedule), argThat(this::assertJKeySet));
        // and:
        verify(store).get(eq(schedule));
        verify(ledger).exists(payerAccount.toGrpcAccountId());
        verify(ledger).get(payerAccount.toGrpcAccountId());
        verify(signingOrder).keysForOtherParties(innerTransactionBody, ScheduleReadyForExecution.PRE_HANDLE_SUMMARY_FACTORY);
        // and:
        verify(txnCtx).setStatus(SUCCESS);
    }

    @Test
    public void setsFailInvalidIfUnhandledException() {
        givenValidTxnCtx();
        // and:
        given(store.addSigners(eq(schedule), any())).willThrow(IllegalArgumentException.class);

        // when:
        subject.doStateTransition();

        // then:
        verify(store).addSigners(eq(schedule), any());
        // and:
        verify(store, never()).get(eq(schedule));
        verify(ledger, never()).exists(payerAccount.toGrpcAccountId());
        verify(ledger, never()).get(payerAccount.toGrpcAccountId());
        verify(signingOrder, never()).keysForOtherParties(innerTransactionBody, ScheduleReadyForExecution.PRE_HANDLE_SUMMARY_FACTORY);
        // and:
        verify(txnCtx).setStatus(FAIL_INVALID);
    }

    @Test
    public void failsWithResponseErrorsOnAddingSigners() {
        // given:
        givenValidTxnCtx();
        // and:
        given(store.addSigners(eq(schedule), any())).willReturn(NOT_OK);

        // when:
        subject.doStateTransition();

        // then:
        verify(store).addSigners(eq(schedule), any());
        // and:
        verify(store, never()).get(eq(schedule));
        verify(ledger, never()).exists(payerAccount.toGrpcAccountId());
        verify(ledger, never()).get(payerAccount.toGrpcAccountId());
        verify(signingOrder, never()).keysForOtherParties(innerTransactionBody, ScheduleReadyForExecution.PRE_HANDLE_SUMMARY_FACTORY);
        // and:
        verify(txnCtx).setStatus(NOT_OK);
    }

    @Test
    public void failsOnInvalidScheduleId() {
        givenCtx(true, false);

        // expect:
        assertEquals(INVALID_SCHEDULE_ID, subject.validate(scheduleSignTxn));
    }

    @Test
    public void failsOnInvalidKeyEncoding() {
        givenCtx(false, true);

        // expect:
        assertEquals(INVALID_KEY_ENCODING, subject.validate(scheduleSignTxn));
    }

    @Test
    public void acceptsValidTxn() {
        givenValidTxnCtx();

        assertEquals(OK, subject.syntaxCheck().apply(scheduleSignTxn));
    }

    @Test
    public void rejectsInvalidScheduleId() {
        givenCtx(true, false);

        assertEquals(INVALID_SCHEDULE_ID, subject.syntaxCheck().apply(scheduleSignTxn));
    }

    @Test
    public void rejectsInvalidKeyEncoding() {
        givenCtx(false, true);

        assertEquals(INVALID_KEY_ENCODING, subject.syntaxCheck().apply(scheduleSignTxn));
    }

    private void givenValidTxnCtx() {
        givenCtx(false, false);
    }

    private void givenCtx(
            boolean invalidScheduleId,
            boolean invalidKeyEncoding
    ) {
        var pair = new KeyPairGenerator().generateKeyPair();
        byte[] pubKey = ((EdDSAPublicKey) pair.getPublic()).getAbyte();
        sigMap = SignatureMap.newBuilder().addSigPair(
                SignaturePair.newBuilder()
                        .setPubKeyPrefix(ByteString.copyFrom(pubKey))
                        .build()
        );
        TransferList transfers = TxnUtils.withAdjustments(
                asAccount("0.0.2"), -2,
                asAccount("0.0.3"), 1,
                asAccount("0.0.4"), 1);

        var cryptoTransferTransactionBody = CryptoTransferTransactionBody.newBuilder()
                .setTransfers(transfers)
                .build();

        try {
            jKeySet = new HashSet<>();
            payerPubKey = KeysHelper.ed25519ToJKey(ByteString.copyFrom(pubKey));
            innerTransactionBody = TransactionBody.parseFrom(cryptoTransferTransactionBody.toByteArray());

            for (SignaturePair signaturePair : sigMap.getSigPairList()) {
                jKeySet.add(KeysHelper.ed25519ToJKey(signaturePair.getPubKeyPrefix()));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        merkleSchedule = new MerkleSchedule(cryptoTransferTransactionBody.toByteArray(), payerAccount, new RichInstant(123, 456));
        merkleSchedule.setPayer(payerAccount);
        merkleSchedule.addSigners(jKeySet);

        merkleAccount = new MerkleAccount();
        merkleAccount.setKey(payerPubKey);

        var builder = TransactionBody.newBuilder();
        var scheduleSign = ScheduleSignTransactionBody.newBuilder()
                .setSigMap(sigMap)
                .setSchedule(schedule);

        if (invalidScheduleId) {
            scheduleSign.clearSchedule();
        }

        if (invalidKeyEncoding) {
            sigMap.clear().addSigPair(SignaturePair.newBuilder().setEd25519(ByteString.copyFromUtf8("some-invalid-signature")).build());
            scheduleSign.setSigMap(sigMap);
        }

        builder.setScheduleSign(scheduleSign);

        scheduleSignTxn = builder.build();
        given(store.get(schedule)).willReturn(merkleSchedule);
        given(ledger.exists(payerAccount.toGrpcAccountId())).willReturn(true);
        given(ledger.get(payerAccount.toGrpcAccountId())).willReturn(merkleAccount);
        given(signingOrder.keysForOtherParties(innerTransactionBody, ScheduleReadyForExecution.PRE_HANDLE_SUMMARY_FACTORY))
                .willReturn(new SigningOrderResult<>(new ArrayList<>(jKeySet)));
        given(accessor.getTxn()).willReturn(scheduleSignTxn);
        given(txnCtx.accessor()).willReturn(accessor);
    }

    private JKey randomPubKey() throws DecoderException {
        var pair = new KeyPairGenerator().generateKeyPair();
        byte[] pubKey = ((EdDSAPublicKey) pair.getPublic()).getAbyte();

        return KeysHelper.ed25519ToJKey(ByteString.copyFrom(pubKey));
    }

    private boolean assertJKeySet(Set<JKey> set) {
        assertEquals(set.size(), jKeySet.size());
        var setIterator = set.iterator();
        var jKeySetIterator = set.iterator();
        while (setIterator.hasNext()) {
            assertTrue(equalUpToDecodability(setIterator.next(), jKeySetIterator.next()));
        }
        return true;
    }
}
