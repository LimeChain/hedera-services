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
import com.hedera.services.state.submerkle.RichInstant;
import com.hedera.services.store.schedule.ScheduleStore;
import com.hedera.services.txns.TransitionLogic;
import com.hedera.services.txns.validation.ScheduleChecks;
import com.hederahashgraph.api.proto.java.ResponseCodeEnum;
import com.hederahashgraph.api.proto.java.ScheduleCreateTransactionBody;
import com.hederahashgraph.api.proto.java.SignaturePair;
import com.hederahashgraph.api.proto.java.TransactionBody;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Predicate;

import static com.hedera.services.keys.KeysHelper.ed25519ToJKey;
import static com.hedera.services.txns.validation.ScheduleChecks.checkAdminKey;
import static com.hedera.services.utils.MiscUtils.asUsableFcKey;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.FAIL_INVALID;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.NOT_SUPPORTED;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.OK;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.SCHEDULE_EXECUTION_ERROR;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.SCHEDULE_EXECUTION_INVALID_ACCOUNT_ID;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.SCHEDULE_EXECUTION_INVALID_PAYER_ACCOUNT_ID;
import static com.hederahashgraph.api.proto.java.ResponseCodeEnum.SUCCESS;

public class ScheduleCreateTransitionLogic extends ScheduleReadyForExecution implements TransitionLogic {
    private static final Logger log = LogManager.getLogger(ScheduleCreateTransitionLogic.class);

    private final Function<TransactionBody, ResponseCodeEnum> SYNTAX_CHECK = this::validate;

    private final TransactionContext txnCtx;

    public ScheduleCreateTransitionLogic(
            HederaLedger ledger,
            HederaSigningOrder signingOrder,
            ScheduleStore store,
            TransactionContext txnCtx) {
        super(ledger, signingOrder, store);
        this.txnCtx = txnCtx;
    }

    @Override
    public void doStateTransition() {
        try {
            transitionFor(txnCtx.accessor().getTxn().getScheduleCreation());
        } catch (InvalidPayerAccountException e) {
            abortWith(SCHEDULE_EXECUTION_INVALID_PAYER_ACCOUNT_ID);
        } catch (InvalidAccountIDException e) {
            abortWith(SCHEDULE_EXECUTION_INVALID_ACCOUNT_ID);
        } catch (InvalidKeysForPartiesException e) {
            abortWith(SCHEDULE_EXECUTION_ERROR);
        } catch (Exception e) {
            log.warn("Unhandled error while processing :: {}!", txnCtx.accessor().getSignedTxn4Log(), e);
            abortWith(FAIL_INVALID);
        }
    }

    private void transitionFor(ScheduleCreateTransactionBody op) throws Exception {
        var scheduledTXPayer = op.hasPayer() ? op.getPayer() : txnCtx.activePayer();
        var schedule = store.getScheduleID(op.getTransactionBody().toByteArray(), scheduledTXPayer);
        if (schedule.isEmpty()) {

            var bytes = op.getTransactionBody().toByteArray();
            var schedulingAccount = txnCtx.activePayer();
            var now = RichInstant.fromJava(txnCtx.consensusTime());
            Optional<JKey> adminKey = Optional.empty();
            if (op.hasAdminKey()) {
                adminKey = asUsableFcKey(op.getAdminKey());
            }

            var result = store.createProvisionally(
                    bytes,
                    scheduledTXPayer,
                    schedulingAccount,
                    now,
                    adminKey);

            if (result.getStatus() != OK) {
                abortWith(result.getStatus());
                return;
            }

            schedule = result.getCreated();
        }

        var created = schedule.get();

        Set<JKey> keys = new HashSet<>();
        for (SignaturePair signaturePair : op.getSigMap().getSigPairList()) {
            keys.add(ed25519ToJKey(signaturePair.getPubKeyPrefix()));
        }

        var outcome = store.addSigners(created, keys);
        if (outcome != OK) {
            abortWith(outcome);
            return;
        }

        if (readyForExecution(created)) {
            // TODO: prepare child tx for execution
        }

        store.commitCreation();
        txnCtx.setCreated(created);
        txnCtx.setStatus(SUCCESS);
    }

    private void abortWith(ResponseCodeEnum cause) {
        if (store.isCreationPending()) {
            store.rollbackCreation();
        }
        txnCtx.setStatus(cause);
    }

    @Override
    public Predicate<TransactionBody> applicability() {
        return TransactionBody::hasScheduleCreation;
    }

    @Override
    public Function<TransactionBody, ResponseCodeEnum> syntaxCheck() {
        return SYNTAX_CHECK;
    }

    public ResponseCodeEnum validate(TransactionBody txnBody) {
        var validity = OK;

        ScheduleCreateTransactionBody op = txnBody.getScheduleCreation();

        if (!op.getExecuteImmediately()) {
            return NOT_SUPPORTED;
        }

        validity = checkAdminKey(
                op.hasAdminKey(), op.getAdminKey()
        );
        if (validity != OK) {
            return validity;
        }

        return ScheduleChecks.validateSignatureMap(op.getSigMap());
    }
}
