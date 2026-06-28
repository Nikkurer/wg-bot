from aiogram.fsm.state import State, StatesGroup


class AddClientStates(StatesGroup):
    waiting_for_name = State()
