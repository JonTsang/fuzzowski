from .ifuzzer import IFuzzer
from fuzzowski import Session
from fuzzowski.mutants.spike import *
from fuzzowski import ITargetConnection, IFuzzLogger, Session, Request, RegexResponse
from urllib.parse import quote_plus


class DNS(IFuzzer):
    """
    DNS Fuzzer
    """

    name = 'dns'

    @staticmethod
    def get_requests() -> List[callable]:
        return [DNS.dns_query]

    @staticmethod
    def define_nodes(*args, **kwargs) -> None:
        s_initialize("query")
        s_word(0, name="TransactionID")
        s_word(0, name="Flags")
        s_word(1, name="Questions", endian=">")
        s_word(0, name="Answer", endian=">")
        s_word(1, name="Authority", endian=">")
        s_word(0, name="Additional", endian=">")

        # ######## Queries ################
        if s_block_start("query"):
            if s_block_start("name_chunk"):
                s_size("string", length=1)
                if s_block_start("string"):
                    s_string("A" * 10)
                s_block_end()
            s_block_end()
            s_repeat("name_chunk", min_reps=2, max_reps=4, step=1, fuzzable=True, name="aName")

            s_group("end", values=["\x00", "\xc0\xb0"])  # very limited pointer fuzzing
            s_word(0xC, name="Type", endian=">")
            s_word(0x8001, name="Class", endian=">")
        s_block_end()
        s_repeat("query", 0, 1000, 40, name="queries")
        s_word(0)

    @staticmethod
    def dns_query(session: Session) -> None:
        session.connect(s_get('query'), callback=DNS.insert_questions)

    @staticmethod
    def insert_questions(target: ITargetConnection, logger: IFuzzLogger, session: Session, node: Request,
                     edge, original: bool, *args, **kwargs) -> bytes:
        node.names["Questions"].value = 1 + node.names["queries"].current_reps
        node.names["Authority"].value = 1 + node.names["auth_nameservers"].current_reps
