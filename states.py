from aiogram.fsm.state import State, StatesGroup


class AddClientStates(StatesGroup):
    waiting_for_name = State()


class AddUserStates(StatesGroup):
    waiting_for_id = State()
    waiting_for_role = State()
