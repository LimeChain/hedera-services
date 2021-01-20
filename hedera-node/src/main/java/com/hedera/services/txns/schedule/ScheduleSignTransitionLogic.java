package com.hedera.services.txns.schedule;

/*-
 * ‌
 * Hedera Services Node
 * ​
 * Copyright (C) 2018 - 2020 Hedera Hashgraph, LLC
 * ​
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ‍
 */

import com.hedera.services.context.TransactionContext;
import com.hedera.services.ledger.HederaLedger;
import com.hedera.services.legacy.core.jproto.JKey;
import com.hedera.services.legacy.exception.InvalidAccountIDException;
import com.hedera.services.legacy.exception.InvalidKeysForPartiesException;
import com.hedera.services.sigs.order.HederaSigningOrder;
import com.hedera.services.sigs.verification.InvalidPayerAccountException;
import com.hedera.services.store.schedule.ScheduleStore;
import com.hedera.services.txns.TransitionLogic;
import com.hedera.services.txns.validation.ScheduleChecks;
import com.hedera.services.utils.SignedTxnAccessor;
import com.hedera.services.utils.TriggeredTxnAccessor;
import com.hederahashgraph.api.proto.java.ResponseCodeEnum;
import com.hederahashgraph.api.proto.java.ScheduleSignTransactionBody;
import com.hederahashgraph.api.proto.java.SignaturePair;
import com.hederahashgraph.api.proto.java.TransactionBody;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.HashSet;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;

import static com.hedera.services.keys.KeysHelper.ed25519ToJKey;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.FAIL_INVALID;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.INVALID_SCHEDULE_ID;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.OK;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.SCHEDULE_EXECUTION_ERROR;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.SCHEDULE_EXECUTION_INVALID_ACCOUNT_ID;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.SCHEDULE_EXECUTION_INVALID_PAYER_ACCOUNT_ID;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.SUCCESS;

public class ScheduleSignTransitionLogic extends ScheduleReadyForExecution implements TransitionLogic {
    private static final Logger log = LogManager.getLogger(ScheduleSignTransitionLogic.class);

    private final Function<TransactionBody, ResponseCodeEnum> SYNTAX_CHECK = this::validate;

    public ScheduleSignTransitionLogic(
            HederaLedger ledger,
            HederaSigningOrder signingOrder,
            ScheduleStore store,
            TransactionContext txnCtx) {
        super(ledger, signingOrder, store, txnCtx);
    }

    @Override
    public void doStateTransition() {
        try {
            transitionFor(txnCtx.accessor().getTxn().getScheduleSign());
        } catch (InvalidPayerAccountException e) {
            txnCtx.setStatus(SCHEDULE_EXECUTION_INVALID_PAYER_ACCOUNT_ID);
        } catch (InvalidAccountIDException e) {
            txnCtx.setStatus(SCHEDULE_EXECUTION_INVALID_ACCOUNT_ID);
        } catch (InvalidKeysForPartiesException e) {
            txnCtx.setStatus(SCHEDULE_EXECUTION_ERROR);
        } catch (Exception e) {
            log.warn("Unhandled error while processing :: {}!", txnCtx.accessor().getSignedTxn4Log(), e);
            txnCtx.setStatus(FAIL_INVALID);
        }
    }

    private void transitionFor(ScheduleSignTransactionBody op) throws Exception {
        Set<JKey> keys = new HashSet<>();
        for (SignaturePair signaturePair : op.getSigMap().getSigPairList()) {
            keys.add(ed25519ToJKey(signaturePair.getPubKeyPrefix()));
        }

        var outcome = store.addSigners(op.getSchedule(), keys);
        if (outcome != OK) {
            txnCtx.setStatus(outcome);
            return;
        }

        if (readyForExecution(op.getSchedule())) {
            outcome = processExecution(op.getSchedule(), store.get(op.getSchedule()).payer().toGrpcAccountId());
        }

        txnCtx.setStatus((outcome == OK) ? SUCCESS : outcome);
    }

    @Override
    public Predicate<TransactionBody> applicability() {
        return TransactionBody::hasScheduleSign;
    }

    @Override
    public Function<TransactionBody, ResponseCodeEnum> syntaxCheck() {
        return SYNTAX_CHECK;
    }

    public ResponseCodeEnum validate(TransactionBody txnBody) {
        ScheduleSignTransactionBody op = txnBody.getScheduleSign();

        if (!op.hasSchedule()) {
            return INVALID_SCHEDULE_ID;
        }

        return ScheduleChecks.validateSignatureMap(op.getSigMap());
    }
}
