import streamlit as st

from honeytool.agents import TOOLS, run_agent
from honeytool.cloud import ATTACKS, make_cloud
from honeytool.guardrail import Monitor

st.set_page_config(page_title="Honeytool", layout="wide")

NO_ATTACK = "No attack"
options = list(ATTACKS) + [NO_ATTACK]


def reset(attack_name):
    st.session_state.attack = attack_name
    st.session_state.monitor = Monitor(make_cloud(None if attack_name == NO_ATTACK else attack_name))
    st.session_state.messages = []


if "monitor" not in st.session_state:
    reset(options[0])

m = st.session_state.monitor

with st.sidebar:
    st.header("Honeytool")
    choice = st.selectbox("Attack", options, index=options.index(st.session_state.attack))
    if choice != st.session_state.attack:
        reset(choice)
        st.rerun()

    st.subheader("Defenses")
    m.tripwire = st.checkbox("Tripwire (block decoy tools)", value=True, key="tripwire")
    m.quarantine = st.checkbox("Quarantine (remove flagged lines)", value=False, key="quarantine")

    st.subheader("Try")
    attack = ATTACKS.get(st.session_state.attack)
    questions = ["Summarize the app-logs bucket", "What servers are running?"]
    if attack:
        questions = [attack["question"]] + [q for q in questions if q != attack["question"]]
    for q in questions:
        if st.button(q):
            st.session_state.pending = q

    if st.button("Reset"):
        reset(st.session_state.attack)
        st.rerun()

    if attack:
        with st.expander("Show the hidden attack"):
            st.code(attack["text"], wrap_lines=True)
    st.caption("Agent tools: " + ", ".join(TOOLS[:4]) + ". Decoys: " + ", ".join(TOOLS[4:]))

question = st.chat_input("Ask the assistant") or st.session_state.pop("pending", None)
if question:
    st.session_state.messages.append(("user", question))
    answer = run_agent(question, m, None if st.session_state.attack == NO_ATTACK else st.session_state.attack)
    st.session_state.messages.append(("assistant", answer))

st.title("Honeytool")

if m.alerts:
    a = m.alerts[-1]
    if a["ran"]:
        st.error(f"Tripwire is off, {a['tool']} ran! Came from: {a['source']}")
    else:
        st.error(f"Blocked {a['tool']} at {a['time']}. Came from: {a['source']}")

left, right = st.columns([3, 2])

with left:
    if not st.session_state.messages:
        st.info("Pick an attack in the sidebar and click one of the buttons under Try")
    for role, text in st.session_state.messages:
        with st.chat_message(role):
            st.markdown(text)

with right:
    st.subheader("Monitor")
    c1, c2, c3 = st.columns(3)
    c1.metric("Tool calls", len(m.log))
    c2.metric("Flagged", len(m.flags))
    c3.metric("Decoy calls", len(m.alerts))

    for a in reversed(m.alerts):
        msg = f"**{'Ran' if a['ran'] else 'Blocked'} {a['tool']}** ({a['time']})  \nsource: `{a['source']}`"
        if a["line"]:
            msg += f"  \nline: `{a['line']}`"
        st.error(msg)

    for f in reversed(m.flags):
        msg = f"**Suspicious data in {f['source']}** ({'removed' if f['removed'] else 'not removed'})"
        for line, reason in f["hits"]:
            msg += f"  \n{reason}: `{line}`"
        st.warning(msg)

    st.write("Tool calls:")
    st.dataframe(list(reversed(m.log)), hide_index=True)
